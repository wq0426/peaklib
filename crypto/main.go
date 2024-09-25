package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

const KEY = "00000000000000000000000000000000"

// AES-256加密
func encrypt(plaintext string) (string, error) {
	// 创建 AES256 加密器
	block, err := aes.NewCipher([]byte(KEY))
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	// 创建加密模式
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	// 创建随机的 nonce
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	// 加密字符串
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	// 将加密后的数据转换为 base64 编码
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(base64Ciphertext string) (string, error) {
	// 创建 AES256 加密器
	block, err := aes.NewCipher([]byte(KEY))
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	// 创建加密模式
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	// 解码 base64 编码的加密数据
	ciphertext, err := base64.StdEncoding.DecodeString(base64Ciphertext)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	// 解密数据
	plaintext, err := gcm.Open(nil, ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():], nil)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	return string(plaintext), nil
}

func main() {
	plaintext := "123"
	encodeStr, err := encrypt(plaintext)
	if err != nil {
		return
	}
	fmt.Println("加密后的字符串:", encodeStr)
	decodeStr, err := decrypt(encodeStr)
	if err != nil {
		return
	}
	fmt.Println("解密后的字符串:", decodeStr)
}
