package cmd

import (
	"path/filepath"

	"github.com/ashutsh/microEncrypter/crypt"
	"github.com/ashutsh/microEncrypter/io"
	"github.com/ashutsh/microEncrypter/utils"
)

type CLI struct {
	// fileEncrypter 	*io.FileEncrypter
	passdump 		*io.PasswordDump
	// other helpers
}
  
func NewCLI(passphrase string) *CLI {
	dump := io.NewPasswordDump(passphrase)
	dump.Load()
	return &CLI{
		// fileEncrypter: io.NewFileEncrypter("data.txt", crypt.NewCrypter()), 
		passdump: dump,
	}
}
 

// Returns list of all files that are encrypted as well as listed in the dump
func (c *CLI) GetListAll() ([]string) {
	return c.passdump.GetFileNamesList()
}


func (c *CLI) AddAndEncryptFile(filename string, tags ...string) error {
	crypter := crypt.NewCrypter()
	genPwd, err := crypter.GeneratePassword()
	if err != nil {
		return err
	}

	// remove when added dispatcher
	if !filepath.IsAbs(filename) {
		filename = utils.LookupFile(filename)
	}

	fileinfo := io.EncryptFileInfo{
		Filename: filename,
		Password: genPwd,
		Tags: tags,
	}

	fileEncrypter := io.NewFileEncrypter(filename, crypter)
	err = fileEncrypter.EncryptExisting(genPwd)
	if err != nil {
		return err
	}

	c.passdump.AddFileInfo(fileinfo)
	c.passdump.Save()
	return nil
}
  
func (c *CLI) DecryptRetriveFile(filename string) ([]byte, error) {
	
	// remove when added dispatcher
	filename, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}

	fileInfo, err := c.passdump.GetFileInfo(filename)
	if err != nil {
		return nil, err
	}
	fileEncrypter := io.NewFileEncrypter(fileInfo.Filename, crypt.NewCrypter())

	databyte, err := fileEncrypter.Decrypt(fileInfo.Password)
	if err != nil {
		return nil, err
	}

	return databyte, nil
}

func (c *CLI) DeleteDecrypt(filename string) error {

	// remove when added dispatcher
	filename, err := filepath.Abs(filename)
	if err != nil {
		return err
	}

	fileInfo, err := c.passdump.GetFileInfo(filename)
	if err != nil {
		return err
	}
	fileEncrypter := io.NewFileEncrypter(fileInfo.Filename, crypt.NewCrypter())

	err = fileEncrypter.DecryptExisting(fileInfo.Password)
	if err != nil {
		return err
	}

	c.passdump.DeleteFileInfo(fileInfo.Filename)
	c.passdump.Save()

	return nil
}

func (c *CLI) UpdateFileInfo(filename string, finfo io.EncryptFileInfo) (io.EncryptFileInfo, error) {
	// remove when added dispatcher
	filename, err := filepath.Abs(filename)
	if err != nil {
		return io.EncryptFileInfo{}, err
	}
	c.passdump.UpdateFileInfo(filename, func(info *io.EncryptFileInfo) {
		if info.Filename != finfo.Filename && finfo.Filename != "" {
			
		}
	})

	err = c.passdump.Save()
	if err != nil {
		return io.EncryptFileInfo{}, err
	}

	return finfo, nil
}