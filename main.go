package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
)

var Chave, err = rsa.GenerateKey(rand.Reader, 2048)

func Encrypt(dados string, chave_publica *rsa.PublicKey) (string, error) {
	dados_encrypt, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, chave_publica, []byte(dados), nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(dados_encrypt), err
}

func Decrypt(dados_encriptados string, chave_privada *rsa.PrivateKey) (string, error) {
	decrypt_64, err := base64.StdEncoding.DecodeString(dados_encriptados)
	if err != nil {
		return "", err
	}
	dados_desencriptados, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, chave_privada, []byte(decrypt_64), nil)
	if err != nil {
		strdecrypt_64 := string(decrypt_64)
		return strdecrypt_64, err
	}
	return string(dados_desencriptados), nil
}

func main() {
	http.HandleFunc("/Encrypt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Erro ao ler o corpo da requisição", http.StatusInternalServerError)
				return
			}
			strbody := string(body)
			dado_crypt, _ := Encrypt(strbody, &Chave.PublicKey)
			fmt.Fprintf(w, "Dados criptografados: %s", dado_crypt)
		} else {
			http.Error(w, "Método inválido", http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/Decrypt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Erro ao ler o corpo da requisição", http.StatusInternalServerError)
				return
			}
			strbody := string(body)
			dado_decrypt, _ := Decrypt(strbody, Chave)
			fmt.Fprintf(w, "Dados descriptografados: %s", dado_decrypt)
		} else {
			http.Error(w, "Método inválido", http.StatusMethodNotAllowed)
		}
	})

	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Println("Server error:", err)
	}

}
