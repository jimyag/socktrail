package main

import (
	"cmp"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

type sortSpec struct {
	key  string
	desc bool
}

func (s *sortSpec) selectColumn(key string) {
	if s.key == key {
		s.desc = !s.desc
		return
	}
	s.key = key
	s.desc = !slices.Contains([]string{"GROUP", "DIR", "SOURCE", "TARGET", "PROTO", "STATE", "DOMAIN / ICMP", "ORIGIN PID", "TARGET PID", "HOST/SNI OR PEER", "PID", "PROCESS"}, key)
}

func (s sortSpec) direction(order int) int {
	if s.desc {
		return -order
	}
	return order
}

func rowTime(row *uiRow, first bool) time.Time {
	var found time.Time
	for _, flow := range row.flows {
		value := flow.Last
		if first {
			value = flow.First
		}
		if value.IsZero() {
			continue
		}
		if found.IsZero() || first && value.Before(found) || !first && value.After(found) {
			found = value
		}
	}
	return found
}

func sortGroups(rows []*uiRow, mode viewMode, spec sortSpec, sortRate bool) {
	slices.SortFunc(rows, func(a, b *uiRow) int {
		var order int
		switch spec.key {
		case "GROUP":
			if mode == viewPID && a.pidID.PID > 0 && b.pidID.PID > 0 {
				order = cmp.Or(cmp.Compare(a.pidID.PID, b.pidID.PID), cmp.Compare(a.pidID.StartNS, b.pidID.StartNS))
			} else if mode == viewSource || mode == viewTarget {
				addrA, errA := netip.ParseAddr(a.label)
				addrB, errB := netip.ParseAddr(b.label)
				if errA == nil && errB == nil {
					order = addrA.Compare(addrB)
				} else {
					order = strings.Compare(a.label, b.label)
				}
			} else {
				order = strings.Compare(a.label, b.label)
			}
		case "RX/s":
			order = cmp.Compare(a.rxRate, b.rxRate)
		case "TX/s":
			order = cmp.Compare(a.txRate, b.txRate)
		case "RX B":
			order = cmp.Compare(a.rx, b.rx)
		case "TX B":
			order = cmp.Compare(a.tx, b.tx)
		case "TCP":
			order = cmp.Compare(a.tcp, b.tcp)
		case "UDP":
			order = cmp.Compare(a.udp, b.udp)
		case "ICMP PKT":
			order = cmp.Compare(a.icmp, b.icmp)
		case "REQ":
			order = cmp.Compare(a.reqs, b.reqs)
		case "PID?":
			order = cmp.Compare(a.unknownPID, b.unknownPID)
		case "FLOWS":
			order = cmp.Compare(len(a.flows), len(b.flows))
		case "FIRST":
			order = rowTime(a, true).Compare(rowTime(b, true))
		case "LAST":
			order = rowTime(a, false).Compare(rowTime(b, false))
		case "HOST/SNI OR PEER":
			order = strings.Compare(groupHint(a, mode), groupHint(b, mode))
		default:
			av, bv := a.rx+a.tx, b.rx+b.tx
			if sortRate {
				av, bv = a.rxRate+a.txRate, b.rxRate+b.txRate
			}
			order = -cmp.Compare(av, bv)
		}
		if spec.key != "" {
			order = spec.direction(order)
		}
		return cmp.Or(order, strings.Compare(a.label, b.label))
	})
}

func compareFlowKey(a, b *flow) int {
	if order := a.Key.A.Compare(b.Key.A); order != 0 {
		return order
	}
	if order := a.Key.B.Compare(b.Key.B); order != 0 {
		return order
	}
	return cmp.Or(cmp.Compare(a.Key.Protocol, b.Key.Protocol), a.First.Compare(b.First))
}

func flowEndpointForSort(f *flow, source bool) netip.AddrPort {
	if f.Initiator.IsValid() {
		if source {
			return f.Initiator
		}
		return f.Target
	}
	if source {
		return f.Key.A
	}
	return f.Key.B
}

func sortFlows(flows []*flow, row *uiRow, spec sortSpec) {
	slices.SortFunc(flows, func(a, b *flow) int {
		var order int
		switch spec.key {
		case "DIR":
			order = strings.Compare(a.Direction, b.Direction)
		case "SOURCE":
			order = flowEndpointForSort(a, true).Compare(flowEndpointForSort(b, true))
		case "TARGET":
			order = flowEndpointForSort(a, false).Compare(flowEndpointForSort(b, false))
		case "PROTO":
			order = strings.Compare(flowProtocol(a), flowProtocol(b))
		case "APP":
			order = strings.Compare(a.AppProtocol, b.AppProtocol)
		case "STATE":
			order = strings.Compare(flowState(a), flowState(b))
		case "DOMAIN / ICMP":
			order = strings.Compare(flowName(a), flowName(b))
		case "IP RX":
			order = cmp.Compare(a.RX, b.RX)
		case "IP TX":
			order = cmp.Compare(a.TX, b.TX)
		case "SYN RTT":
			order = cmp.Compare(a.Health.SynRTT, b.Health.SynRTT)
		case "RETX":
			ra, _ := retransmits(a)
			rb, _ := retransmits(b)
			order = cmp.Compare(ra, rb)
		case "PID RX":
			order = cmp.Compare(a.IO[row.pidID].RX, b.IO[row.pidID].RX)
		case "PID TX":
			order = cmp.Compare(a.IO[row.pidID].TX, b.IO[row.pidID].TX)
		case "ORIGIN PID":
			order = cmp.Or(cmp.Compare(a.Client.PID, b.Client.PID), cmp.Compare(a.Client.StartNS, b.Client.StartNS))
		case "TARGET PID":
			order = cmp.Or(cmp.Compare(a.Server.PID, b.Server.PID), cmp.Compare(a.Server.StartNS, b.Server.StartNS))
		case "FIRST":
			order = a.First.Compare(b.First)
		case "LAST":
			order = a.Last.Compare(b.Last)
		default:
			order = -cmp.Compare(a.RX+a.TX, b.RX+b.TX)
		}
		if spec.key != "" {
			order = spec.direction(order)
		}
		return cmp.Or(order, compareFlowKey(a, b))
	})
}

func sortProcesses(processes []participant, c *collector, spec sortSpec) {
	slices.SortFunc(processes, func(a, b participant) int {
		var order int
		switch spec.key {
		case "PROCESS":
			order = strings.Compare(a.Name, b.Name)
		case "SOCKET RX B":
			order = cmp.Compare(c.pidIO[a.id()].RX, c.pidIO[b.id()].RX)
		case "SOCKET TX B":
			order = cmp.Compare(c.pidIO[a.id()].TX, c.pidIO[b.id()].TX)
		default:
			order = cmp.Compare(a.PID, b.PID)
		}
		if spec.key != "" {
			order = spec.direction(order)
		}
		return cmp.Or(order, cmp.Compare(a.PID, b.PID), cmp.Compare(a.StartNS, b.StartNS))
	})
}

func distinguishProcessNames(processes []participant) {
	byPID := make(map[int][]int)
	for index, process := range processes {
		byPID[process.PID] = append(byPID[process.PID], index)
	}
	for _, indices := range byPID {
		if len(indices) < 2 {
			continue
		}
		slices.SortFunc(indices, func(a, b int) int { return cmp.Compare(processes[a].StartNS, processes[b].StartNS) })
		for generation, index := range indices {
			processes[index].Name += " #" + strconv.Itoa(generation+1)
		}
	}
}
