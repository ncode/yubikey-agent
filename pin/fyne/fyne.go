package fyne

import (
	"fmt"

	"fyne.io/fyne"
	"fyne.io/fyne/app"
	"fyne.io/fyne/layout"
	"fyne.io/fyne/widget"
)

func App() {
	myApp := app.New()
	fyne.CurrentApp().Settings().SetTheme(newCustomTheme())

	myWindow := myApp.NewWindow("VBox Layout")
	myWindow.SetTitle("YubiKey #sassdqewe (3 tries remaining)")

	password := fyne.NewContainerWithLayout(layout.NewGridLayoutWithColumns(2))
	passwordLabel := widget.NewLabel("Please enter your PIN: ")
	passwordText := widget.NewPasswordEntry()
	password.AddObject(passwordLabel)
	password.AddObject(passwordText)
	//l := fyne.NewContainerWithLayout(layout.NewMaxLayout(), passwordText)
	//password.Add(l)

	buttons := fyne.NewContainerWithLayout(layout.NewHBoxLayout())
	cancelButton := widget.NewButton("Cancel", func() {
		fmt.Println("auth func()")
		//authenticated = true
		//myWindow.Hide()
		//go showTasks(myApp)
	})
	cancelButton.Alignment = widget.ButtonAlignTrailing
	okButton := widget.NewButton("OK", func() {
		fmt.Println(passwordText.Text)
		//authenticated = true
		//myWindow.Hide()
		//go showTasks(myApp)
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
	myWindow.Resize(fyne.NewSize(400, 100))
	myWindow.ShowAndRun()
}
