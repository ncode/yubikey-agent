package fyne

import (
	"fmt"

	"fyne.io/fyne"
	"fyne.io/fyne/app"
	"fyne.io/fyne/layout"
	"fyne.io/fyne/widget"
)

type passwordEntry struct {
	widget.Entry
}

func newPasswordEntry() *passwordEntry {
	p := &passwordEntry{}
	p.ExtendBaseWidget(p)
	p.Password = true
	return p
}

func (e *passwordEntry) onEnter() {
	fmt.Println(e.Entry.Text)
	e.Entry.SetText("")
}

func (e *passwordEntry) TypedKey(key *fyne.KeyEvent) {
	switch key.Name {
	case fyne.KeyReturn:
		e.onEnter()
	default:
		e.Entry.TypedKey(key)
	}
}

func App() {
	yubiKeyPin := app.New()
	fyne.CurrentApp().Settings().SetTheme(newCustomTheme())

	window := yubiKeyPin.NewWindow("YubiKey PIN")
	window.SetTitle("YubiKey #sassdqewe (3 tries remaining)")

	password := fyne.NewContainerWithLayout(layout.NewGridLayoutWithColumns(2))
	passwordLabel := widget.NewLabel("Please enter your PIN: ")
	passwordText := newPasswordEntry()
	password.AddObject(passwordLabel)
	password.AddObject(passwordText)
	passwordText.OnChanged = func(s string) {
		if len(passwordText.Text) > 8 {
			passwordText.SetText(passwordText.Text[0:8])
		}
	}

	buttons := fyne.NewContainerWithLayout(layout.NewHBoxLayout())
	cancelButton := widget.NewButton("Cancel", func() {
		yubiKeyPin.Quit()
	})
	cancelButton.Alignment = widget.ButtonAlignTrailing
	okButton := widget.NewButton("OK", func() {
		fmt.Println(passwordText.Text)
		passwordText.SetText("")
	})
	okButton.Alignment = widget.ButtonAlignTrailing
	buttons.AddObject(layout.NewSpacer())
	buttons.AddObject(cancelButton)
	buttons.AddObject(okButton)

	box := fyne.NewContainerWithLayout(layout.NewVBoxLayout(), password, buttons)
	center := fyne.NewContainerWithLayout(layout.NewCenterLayout(), box)

	window.SetContent(center)
	window.SetPadded(true)
	window.SetFixedSize(true)
	window.Resize(fyne.NewSize(350, 100))
	window.ShowAndRun()
}
