package io

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/ashutsh/microEncrypter/crypt"
)


type FileEncrypter struct {
	filename string
	crypter  *crypt.Crypter // crypt helper 
}
  
func NewFileEncrypter(filename string, crypter *crypt.Crypter) *FileEncrypter {
	return &FileEncrypter{
		filename: filename,
		crypter: crypter,
	}
}

func (f *FileEncrypter) EncryptExisting(passphrase string) error {
	data, err := f.readFile()
	if err != nil {
		return err
	} 
	
	err = f.Encrypt(data, passphrase)
	if err != nil {
		return err
	} 

	return nil
} 

func (f *FileEncrypter) DecryptExisting(passphrase string) error {
	
	data, err := f.Decrypt(passphrase)
	if err != nil {
		return err
	}
	f.writeFile(data)

	return nil  
}

func (f *FileEncrypter) Encrypt(data []byte, passphrase string) error {
	
	ciphertext, err := f.crypter.EncryptEncode(data, passphrase)
	if err != nil {
		return err
	}

	err = f.writeFile(ciphertext)
	if err != nil {
		return err
	}

	return nil
}

func (f *FileEncrypter) Decrypt(passphrase string) ([]byte, error) {
	encrypted, err := f.readFile()
	if err != nil {
		return nil, err
	}
	data, err := f.crypter.DecodeDecrypt(encrypted, passphrase)
	if err != nil {
		return nil, err
	}
	
	return data, nil
}



func (f *FileEncrypter) readFile() ([]byte, error) {
	filebyte, err := os.ReadFile(f.filename)
	if err != nil {
		return nil, err
	}

	return filebyte, nil
}

func (f *FileEncrypter) writeFile(data []byte) (error) {
	err := os.WriteFile(f.filename, data, 0666) 
	if err != nil {
		return err
	}

	return nil
}

// ------------------------------------------------------------------------------------------------------------------

// EncryptFileInfo holds metadata for an encrypted file
type EncryptFileInfo struct {
	Filename string
	Password string
	Tags     []string
}
  
const passDumpFilename = "C:/Users/DELL/Go/src/microEncrypter/data/dump.txt"

  // PasswordDump manages the file info map
type PasswordDump struct {
	passphrase 	string
	fileInfos  	map[string]EncryptFileInfo 
	// crypter 	*crypt.Crypter
}
  
func NewPasswordDump(passphrase string) *PasswordDump {
	return &PasswordDump{
	  passphrase: passphrase,
	  fileInfos: make(map[string]EncryptFileInfo),
	//   crypter: crypt.NewCrypter(),
	}
}
  
// AddFileInfo adds a new encrypted file metadata
func (p *PasswordDump) AddFileInfo(info EncryptFileInfo) {
	p.fileInfos[info.Filename] = info
}
  
// UpdateFileInfo updates existing file metadata
func (p *PasswordDump) UpdateFileInfo(filename string, updateFn func(info *EncryptFileInfo)) {
	info := p.fileInfos[filename]
	updateFn(&info)	
	if info.Filename == filename {
		p.fileInfos[filename] = info
	} else if info.Filename != filename {
		p.fileInfos[info.Filename] = info
		delete(p.fileInfos, filename)
	}
}

// UpdateFileInfo updates existing filename to a new one
// func (p *PasswordDump) UpdateFileName(oldFilename string, newFilename string) {
// 	info := p.fileInfos[oldFilename]
// 	delete(p.fileInfos, oldFilename)
// 	p.fileInfos[newFilename] = info
// }
  
// DeleteFileInfo removes file metadata
func (p *PasswordDump) DeleteFileInfo(filename string) {
	delete(p.fileInfos, filename) 
}
  
// GetFileInfo retrieves file metadata
func (p *PasswordDump) GetFileInfo(filename string) (EncryptFileInfo, error) {
	
	filename, err := filepath.Abs(filename)
	if err != nil {
		return EncryptFileInfo{}, err
	}


	return p.fileInfos[filename], nil
	// fileinfo := p.fileInfos[filename]
	// return /* p.fileInfos[filename] */ &fileinfo
}

func (p *PasswordDump) GetFileNamesList() []string {
	list := make([]string, 0)
	for i := range p.fileInfos {
		i = filepath.Base(i)
		list = append(list, i)
	}
	
	return list
}
  
// Load reads and decrypts data from disk
func (p *PasswordDump) Load() error {
	// read encrypted data, decrypt
	dumpcrypter := NewFileEncrypter(passDumpFilename, crypt.NewCrypter())
  	deciphertxt, err := dumpcrypter.Decrypt(p.passphrase)
	if err != nil {
		return err
	}

	// unmarshal into p.fileInfos
	err = json.Unmarshal(deciphertxt, &p.fileInfos)
	if err != nil {
		return err
	}

	return nil  
}
  
// Save encrypts and writes data to disk 
func (p *PasswordDump) Save() error {
	// marshal p.fileInfos
	jsonBytes, err := json.MarshalIndent(p.fileInfos, "", "\t")
	if err != nil {
		return err
	}

	// encrypt and write to file
	dumpcrypter := NewFileEncrypter(passDumpFilename, crypt.NewCrypter())
	err = dumpcrypter.Encrypt(jsonBytes, p.passphrase)
	if err != nil {
		return err
	}

	return nil
}