package jumbocli

import (
	"JumboChain/accounts"
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli"
)

var app = cli.NewApp()

func info() {
	app.Name = "Jumbo"
	app.Usage = "An application to interact with Jumbo Chain"
	app.Author = "Vaikr"
	app.Version = "1.0"
}

func commands() {
	app.Commands = []cli.Command{
		{
			Name:    "Create Account",
			Aliases: []string{"newaccount"},
			Usage:   "Create a new account",
			Action: func(c *cli.Context) {
				a := accounts.NewAccount()
				fmt.Println(a)
			},
		},
	}
}

func CliComm() { 
	info()
	commands()
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
