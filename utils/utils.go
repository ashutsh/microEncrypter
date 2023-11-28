package utils

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/term"
)

func YNQues(deliminator, msg string) bool {
	if deliminator == "" {
		deliminator = ": "
	}
	fmt.Print(msg)
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(deliminator)
		ans, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println(err)
			continue
		} 
		ans = strings.ToLower(ans)
		ans = strings.TrimSpace(ans)
		if ans == "yes" || ans == "y" {
			return true
		} else if ans == "no" || ans == "n" {
			return false
		}
	}
}

func LookupFile(filename string) string {
	if !filepath.IsAbs(filename) {
		f, err := filepath.Abs(filename)
		// f, err := os.Stat(filename)
		if err != nil {
			fmt.Println(err)
			return ""
		}
		fmt.Println(f)
		if !YNQues("", "We are going to use this as the filename. Would you like to continue?") {
			return ""
		} else {
			return f
		}
	} 

	return filename
}


// This func can be used to get user input of passwords or credentials. 
// 
// When called it doesn't do the local echo thing like linux and also, you can either put a message to be displayed just before when the user has to input 
// credentials or you can just leave it as "" and the default 'Enter Password: ' will be called. 
// 
// Also this function calls \n after the user enters the credentials and hits enter. Else any next print statement will be printed just where you entered the password.
// 
// This function just used the golang.org/x/term package's ReadPassword func. So you can check it out for more details.
func PromtGetPassword(msg string) (string, error) {

	if msg == "" {
		msg = "Enter Password: "
	}

	fmt.Print(msg)
    password, err := term.ReadPassword(int(syscall.Stdin))
    if err != nil {
		return "", err
    }
	fmt.Println()
    // fmt.Printf("\nPassword is: %s\n", password)

	return string(password), nil
}


