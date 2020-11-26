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
	e := &passwordEntry{}
	e.ExtendBaseWidget(e)
	e.Password = true
	return e
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
	myApp := app.New()
	fyne.CurrentApp().Settings().SetTheme(newCustomTheme())

	myWindow := myApp.NewWindow("VBox Layout")
	myWindow.SetTitle("YubiKey #sassdqewe (3 tries remaining)")

	password := fyne.NewContainerWithLayout(layout.NewGridLayoutWithColumns(2))
	passwordLabel := widget.NewLabel("Please enter your PIN: ")
	passwordText := newPasswordEntry()
	password.AddObject(passwordLabel)
	password.AddObject(passwordText)

	buttons := fyne.NewContainerWithLayout(layout.NewHBoxLayout())
	cancelButton := widget.NewButton("Cancel", func() {
		myApp.Quit()
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
	//		myWindow.Hide()
	vbox := fyne.NewContainerWithLayout(layout.NewVBoxLayout(), password, buttons)
	vbox.Resize(fyne.NewSize(400, 100))
	pad := fyne.NewContainerWithLayout(layout.NewCenterLayout(), vbox)
	myWindow.SetContent(pad)
	myWindow.SetPadded(true)
	myWindow.SetFixedSize(true)
	myWindow.CenterOnScreen()
	myWindow.Resize(fyne.NewSize(350, 100))
	myWindow.ShowAndRun()
}
