package main

import (
	"net/netip"
	"testing"
)

func TestDecodeUIInputHandlesSplitMouseAndEscape(t *testing.T) {
	if _, consumed, incomplete := decodeUIInput([]byte("\x1b[<0;12;"), false); consumed != 0 || !incomplete {
		t.Fatal("split mouse sequence was consumed before completion")
	}
	press, consumed, incomplete := decodeUIInput([]byte("\x1b[<0;12;8M"), false)
	if incomplete || consumed != len("\x1b[<0;12;8M") || press.mouse != (mouseInput{action: mousePress, x: 11, y: 7}) {
		t.Fatalf("mouse press decoded incorrectly: %+v consumed=%d incomplete=%t", press, consumed, incomplete)
	}
	for _, tc := range []struct {
		sequence string
		action   mouseAction
	}{
		{"\x1b[<32;12;20M", mouseDrag},
		{"\x1b[<0;12;20m", mouseRelease},
		{"\x1b[<64;12;20M", mouseWheelUp},
		{"\x1b[<65;12;20M", mouseWheelDown},
		{"\x1b[<66;12;20M", mouseWheelLeft},
		{"\x1b[<67;12;20M", mouseWheelRight},
	} {
		input, n, partial := decodeUIInput([]byte(tc.sequence), false)
		if partial || n != len(tc.sequence) || input.mouse.action != tc.action {
			t.Fatalf("%q decoded incorrectly: %+v consumed=%d partial=%t", tc.sequence, input, n, partial)
		}
	}
	if _, _, incomplete := decodeUIInput([]byte("\x1b"), false); !incomplete {
		t.Fatal("lone Escape key was consumed without waiting for an arrow or mouse sequence")
	}
	if input, n, incomplete := decodeUIInput([]byte("\x1b"), true); incomplete || n != 1 || input.key != "esc" {
		t.Fatalf("lone Escape key was lost: %+v consumed=%d incomplete=%t", input, n, incomplete)
	}
	if input, n, incomplete := decodeUIInput([]byte("\x1b[D"), false); incomplete || n != 3 || input.key != "left" {
		t.Fatalf("left arrow was lost: %+v consumed=%d incomplete=%t", input, n, incomplete)
	}
	for sequence, key := range map[string]string{"\x1b[5~": "pageup", "\x1b[6~": "pagedown", "\x1b[Z": "shift-tab", "\x1b[1;2Z": "shift-tab"} {
		if input, n, incomplete := decodeUIInput([]byte(sequence), false); incomplete || n != len(sequence) || input.key != key {
			t.Fatalf("%q decoded incorrectly: %+v consumed=%d incomplete=%t", sequence, input, n, incomplete)
		}
	}
	if input, _, _ := decodeUIInput([]byte("\x1b[<68;12;20M"), false); input.mouse.action != mouseWheelUp || !input.mouse.shift {
		t.Fatalf("shifted wheel did not retain its modifier: %+v", input)
	}
}

func TestMouseSelectsRowsTabsAndResizesDetail(t *testing.T) {
	a := netip.MustParseAddrPort("127.0.0.1:51000")
	b := netip.MustParseAddrPort("127.0.0.1:8080")
	d := netip.MustParseAddrPort("127.0.0.1:8081")
	e := netip.MustParseAddrPort("127.0.0.1:8082")
	first := &flow{Key: keyFor(a, b, 6), Client: participant{PID: 101, StartNS: 1000, Name: "first"}}
	second := &flow{Key: keyFor(a, d, 6), Client: participant{PID: 202, StartNS: 2000, Name: "second"}}
	third := &flow{Key: keyFor(a, e, 6), Client: participant{PID: 101, StartNS: 1000, Name: "first"}}
	c := &collector{flows: map[flowKey]*flow{first.Key: first, second.Key: second, third.Key: third}}
	u := &terminalUI{mode: viewPID, screenWidth: 120, screenHeight: 40, dividerY: 19, bottomStart: 20, bottomHeight: 19}
	u.handleMouse(mouseInput{action: mousePress, x: 3, y: 5}, c)
	if u.selected != 1 {
		t.Fatalf("second table row did not select second PID: %d", u.selected)
	}
	u.handleMouse(mouseInput{action: mouseWheelUp, x: 3, y: 5}, c)
	if u.selected != 0 {
		t.Fatalf("wheel did not move to first PID: %d", u.selected)
	}
	u.mainCanvas, u.detailCanvas = 180, 230
	u.handleMouse(mouseInput{action: mouseWheelDown, shift: true, x: 3, y: 5}, c)
	if u.mainX != 30 || u.detailX != 0 {
		t.Fatalf("shift-wheel did not scroll main columns: main=%d detail=%d", u.mainX, u.detailX)
	}
	var lines []string
	u.renderBottom(&lines, u.rows(c, viewPID), c)
	u.handleMouse(mouseInput{action: mousePress, x: 3, y: u.bottomStart + 3}, c)
	if u.selectedFlow != 1 || !u.focusBottom {
		t.Fatalf("click did not select the second connection: flow=%d focused=%t", u.selectedFlow, u.focusBottom)
	}
	u.handleMouse(mouseInput{action: mouseWheelUp, x: 3, y: u.bottomStart + 3}, c)
	if u.selectedFlow != 0 {
		t.Fatalf("wheel did not scroll connections: flow=%d", u.selectedFlow)
	}
	u.handleMouse(mouseInput{action: mouseWheelRight, x: 3, y: u.bottomStart + 3}, c)
	if u.detailX != 30 {
		t.Fatalf("horizontal wheel did not scroll connection columns: %d", u.detailX)
	}
	u.handleMouse(mouseInput{action: mousePress, x: u.tabHits[1].start, y: u.bottomStart}, c)
	if u.tab != 1 {
		t.Fatalf("mouse did not switch bottom tab: %d", u.tab)
	}
	u.handleMouse(mouseInput{action: mousePress, x: 4, y: 19}, c)
	u.handleMouse(mouseInput{action: mouseDrag, x: 4, y: 27}, c)
	u.handleMouse(mouseInput{action: mouseRelease, x: 4, y: 27}, c)
	if u.dragging || u.tableRows != 23 {
		t.Fatalf("divider drag did not resize detail: dragging=%t tableRows=%d", u.dragging, u.tableRows)
	}
	u.dividerY = 27 // The next render places the divider at the dragged position.
	u.handleMouse(mouseInput{action: mousePress, x: 4, y: 27}, c)
	u.handleMouse(mouseInput{action: mouseDrag, x: 4, y: 1}, c)
	u.handleMouse(mouseInput{action: mouseRelease, x: 4, y: 1}, c)
	if u.tableRows != 2 {
		t.Fatalf("divider moved above its minimum table height: %d", u.tableRows)
	}
}
