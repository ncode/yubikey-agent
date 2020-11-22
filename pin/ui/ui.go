package ui

import (
	"fmt"

	"github.com/andlabs/ui"
)

// ReadPIN spawn a simple ui and read the user PIN for the YubiKey
func ReadPIN() {
	ui.Main(setupUI)
}

func setupUI() {
	windowLabel := "Yubico YubiKey FIDO+CCID #11512971"
	mainWindow := ui.NewWindow(windowLabel, 500, 200, false)
	mainWindow.OnClosing(func(*ui.Window) bool {
		ui.Quit()
		return true
	})
	ui.OnShouldQuit(func() bool {
		mainWindow.Destroy()
		return true
	})
	mainWindow.SetBorderless(true)

	passwordContainer := ui.NewVerticalBox()
	passwordContainer.SetPadded(true)

	passwordGroup := ui.NewGroup("")
	passwordGroup.SetMargined(true)

	passwordBox := ui.NewVerticalBox()
	passwordBox.SetPadded(true)

	passwordForm := ui.NewForm()
	passwordForm.SetPadded(true)

	password := ui.NewPasswordEntry()
	passwordForm.Append("Please entry your PIN: ", password, false)

	buttonsBox := ui.NewHorizontalBox()
	buttonsBox.SetPadded(true)

	okMessageButton := ui.NewButton("OK")
	cancelMessageButton := ui.NewButton("Cancel")

	grid := ui.NewGrid()
	grid.SetPadded(true)

	buttonsBox.Append(cancelMessageButton, false)
	buttonsBox.Append(okMessageButton, false)

	grid.Append(buttonsBox, 0, 1, 1, 1, false, ui.AlignEnd, false, ui.AlignEnd)
	passwordBox.Append(passwordForm, false)
	passwordBox.Append(grid, false)
	passwordGroup.SetChild(passwordBox)

	messageGroup := ui.NewGroup("Message")
	messageGroup.SetMargined(true)

	vbMessage := ui.NewVerticalBox()
	vbMessage.SetPadded(true)

	messageLabel := ui.NewLabel("")
	vbMessage.Append(messageLabel, false)

	messageGroup.SetChild(vbMessage)

	passwordContainer.Append(passwordGroup, false)
	passwordContainer.Append(messageGroup, false)

	mainWindow.SetChild(passwordContainer)

	okMessageButton.OnClicked(func(*ui.Button) {
		// Update the UI directly as it is called from the main thread
		messageLabel.SetText(password.Text())
	})

	password.OnChanged(func(*ui.Entry) {
		fmt.Println("1")
		messageLabel.SetText(password.Text())
	})

	cancelMessageButton.OnClicked(func(*ui.Button) {
		ui.Quit()
	})

	mainWindow.Show()
}
