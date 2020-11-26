package fyne

import (
	"image/color"

	"fyne.io/fyne"
	"fyne.io/fyne/theme"
)

// customTheme is based upon the custom theme example in the fyne_demo application. It is generated from the
// current template in the prettyfyne theme editor and should be useable with a fyne applicaton without any
// additional requirements.
// It can be applied by calling: "fyne.CurrentApp().Settings().SetTheme(newCustomTheme())" after the app is running.
type customTheme struct {
}

func (customTheme) BackgroundColor() color.Color {
	return &color.RGBA{R: 0x1e, G: 0x1e, B: 0x1e, A: 0xff}
}

func (customTheme) ButtonColor() color.Color {
	return &color.RGBA{R: 0x14, G: 0x14, B: 0x14, A: 0xff}
}

func (customTheme) DisabledButtonColor() color.Color {
	return &color.RGBA{R: 0xf, G: 0xf, B: 0x11, A: 0xff}
}

func (customTheme) HyperlinkColor() color.Color {
	return &color.RGBA{R: 0xaa, G: 0x64, B: 0x14, A: 0x40}
}

func (customTheme) TextColor() color.Color {
	return &color.RGBA{R: 0xc8, G: 0xc8, B: 0xc8, A: 0xff}
}

func (customTheme) DisabledTextColor() color.Color {
	return &color.RGBA{R: 0x9b, G: 0x9b, B: 0x9b, A: 0x7f}
}

func (customTheme) IconColor() color.Color {
	return &color.RGBA{R: 0x96, G: 0x50, B: 0x0, A: 0xff}
}

func (customTheme) DisabledIconColor() color.Color {
	return &color.RGBA{R: 0x9b, G: 0x9b, B: 0x9b, A: 0x7f}
}

func (customTheme) PlaceHolderColor() color.Color {
	return &color.RGBA{R: 0x96, G: 0x50, B: 0x0, A: 0xff}
}

func (customTheme) PrimaryColor() color.Color {
	return &color.RGBA{R: 0x6e, G: 0x28, B: 0x0, A: 0x7f}
}

func (customTheme) HoverColor() color.Color {
	return &color.RGBA{R: 0x0, G: 0x0, B: 0x0, A: 0xff}
}

func (customTheme) FocusColor() color.Color {
	return &color.RGBA{R: 0x63, G: 0x63, B: 0x63, A: 0xff}
}

func (customTheme) ScrollBarColor() color.Color {
	return &color.RGBA{R: 0x23, G: 0x23, B: 0x23, A: 0x8}
}

func (customTheme) ShadowColor() color.Color {
	return &color.RGBA{R: 0x0, G: 0x0, B: 0x0, A: 0x40}
}

func (customTheme) TextSize() int {
	return 12
}

// TODO: for now, demo still returns default fonts
func (customTheme) TextFont() fyne.Resource {
	return theme.DefaultTextFont()
}

func (customTheme) TextBoldFont() fyne.Resource {
	return theme.DefaultTextBoldFont()
}

func (customTheme) TextItalicFont() fyne.Resource {
	return theme.DefaultTextItalicFont()
}

func (customTheme) TextBoldItalicFont() fyne.Resource {
	return theme.DefaultTextBoldItalicFont()
}

func (customTheme) TextMonospaceFont() fyne.Resource {
	return theme.DefaultTextMonospaceFont()
}

func (customTheme) Padding() int {
	return 4
}

func (customTheme) IconInlineSize() int {
	return 22
}

func (customTheme) ScrollBarSize() int {
	return 10
}

func (customTheme) ScrollBarSmallSize() int {
	return 4
}

func newCustomTheme() fyne.Theme {
	return &customTheme{}
}
