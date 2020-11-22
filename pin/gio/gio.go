package gio

// SPDX-License-Identifier: Unlicense OR MIT

import (
	"fmt"
	"image/color"
	"log"
	"os"

	"gioui.org/app"
	"gioui.org/font/gofont"
	"gioui.org/io/system"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

func Run(title string) string {
	go func() {
		w := app.NewWindow(app.Size(unit.Dp(600), unit.Dp(200)), app.MaxSize(unit.Dp(600), unit.Dp(200)), app.MinSize(unit.Dp(600), unit.Dp(200)), app.Title(title))
		if err := loop(w); err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}()
	app.Main()
	p := pin
	pin = ""
	return p
}

func loop(w *app.Window) error {
	th := material.NewTheme(gofont.Collection())
	th.TextSize = unit.Sp(14)
	var ops op.Ops
	for {
		select {
		case e := <-w.Events():
			switch e := e.(type) {
			case system.ClipboardEvent:
				fmt.Println("meh")
				lineEditor.SetText(e.Text)
			case system.DestroyEvent:
				return e.Err
			case system.FrameEvent:
				gtx := layout.NewContext(&ops, e)
				for okButton.Clicked() {
					pin = lineEditor.Text()
				}
				for cancelButton.Clicked() {
					w.Close()
				}
				kitchen(gtx, th)
				e.Frame(gtx.Ops)
			}
		}
	}
}

var (
	lineEditor = &widget.Editor{
		SingleLine: true,
		Submit:     true,
		Mask:       '*',
	}
	okButton     = new(widget.Clickable)
	cancelButton = new(widget.Clickable)
	list         = &layout.List{
		Axis: layout.Vertical,
	}

	pin = ""
)

type (
	D = layout.Dimensions
	C = layout.Context
)

func kitchen(gtx layout.Context, th *material.Theme) layout.Dimensions {
	for _, e := range lineEditor.Events() {
		if e, ok := e.(widget.SubmitEvent); ok {
			pin = e.Text
			lineEditor.SetText("")
		}
	}
	widgets := []layout.Widget{
		func(gtx C) D {
			in := layout.UniformInset(unit.Dp(8))
			return layout.Flex{Alignment: layout.End}.Layout(gtx,
				layout.Rigid(func(gtx C) D {
					return in.Layout(gtx, func(gtx C) D {
						return material.Label(th, th.TextSize, "Please enter your PIN: ").Layout(gtx)
					})
				}),
				layout.Rigid(func(gtx C) D {
					e := material.Editor(th, lineEditor, "                                                                   ")
					e.Font.Style = text.Italic
					border := widget.Border{Color: color.NRGBA{A: 0xff}, CornerRadius: unit.Dp(8), Width: unit.Px(2)}
					return border.Layout(gtx, func(gtx C) D {
						return in.Layout(gtx, e.Layout)
					})
				}),
			)
		},
		func(gtx C) D {
			in := layout.Inset{Left: unit.Dp(290)}
			return layout.Flex{Alignment: layout.End}.Layout(gtx,
				layout.Rigid(func(gtx C) D {
					return in.Layout(gtx, func(gtx C) D {
						return material.Button(th, okButton, "OK").Layout(gtx)
					})
				}),
				layout.Rigid(func(gtx C) D {
					in := layout.Inset{Left: unit.Dp(8)}
					return in.Layout(gtx, func(gtx C) D {
						cancel := material.Button(th, cancelButton, "Cancel")
						cancel.Background = color.NRGBA{A: 0xDD, R: 0x72, G: 0x00, B: 0x00}
						return cancel.Layout(gtx)
					})
				}),
			)
		},
	}

	return list.Layout(gtx, len(widgets), func(gtx C, i int) D {
		return layout.UniformInset(unit.Dp(16)).Layout(gtx, widgets[i])
	})
}
