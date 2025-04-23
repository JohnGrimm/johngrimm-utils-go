package johngrimmutilsgo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	MathRand "math/rand"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	http1 "github.com/bogdanfinn/fhttp"

	"github.com/avast/retry-go"
	"github.com/fatih/color"
	"github.com/gofiber/fiber/v2"
	"github.com/tidwall/gjson"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

func GenIp() string {
	buf := make([]byte, 4)
	ipBuf := MathRand.Uint32()

	binary.LittleEndian.PutUint32(buf, ipBuf)
	ip := net.IP(buf)

	return ip.String()
}

func ValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func CheckAttempts(c *fiber.Ctx, ATTEMPS, now int) error {
	if now >= ATTEMPS {
		return fmt.Errorf("Error on Attemps")
	}
	return nil
}

func isMn(r rune) bool {
	return unicode.Is(unicode.Mn, r) // Mn: nonspacing marks
}

var t = transform.Chain(norm.NFD, transform.RemoveFunc(isMn), norm.NFC)

func RandomizarString(seed string) string {
	result := make([]byte, len(seed))
	for i := range result {
		result[i] = seed[MathRand.Intn(len(seed))]
	}
	return string(result)
}

func UrlEncode(s string) string {
	return url.QueryEscape(s)
}

func UnescapeUTF8(inStr string) (outStr string, err error) {
	jsonStr := `"` + strings.ReplaceAll(inStr, `"`, `\"`) + `"`
	err = json.Unmarshal([]byte(jsonStr), &outStr)
	return
}

func Normalize(text string) string {
	r := transform.NewReader(strings.NewReader(text), t)
	outUtf8, err := io.ReadAll(r)
	if err != nil {
		return "John Grimm"
	}
	return string(outUtf8)
}

func GetStr(data string, init string, end string) string {
	if !strings.Contains(data, init) || !strings.Contains(data, end) {
		return ""
	}
	return strings.Split(strings.Split(data, init)[1], end)[0]
}

func GenerateDispositivoID() string {
	// Generate random bytes
	bytes := make([]byte, 8)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err)
	}

	// Convert bytes to hexadecimal strings
	id1 := strings.ToUpper(hex.EncodeToString(bytes[:4]))
	id2 := strings.ToUpper(hex.EncodeToString(bytes[4:]))

	// Concatenate the two parts with a pipe separator
	dispositivoID := fmt.Sprintf("%s|%s", id1, id2)

	return dispositivoID
}

func RandomHex(n int) string {
	letters := []rune("0123456789abcdef")
	s := make([]rune, n)
	for i := range s {
		s[i] = letters[MathRand.Intn(len(letters))]
	}
	return string(s)
}

func IndexOf(slice []string, value string) int {
	for i, v := range slice {
		if v == value {
			return i
		}
	}
	return -1
}

func Rand(min int, max int) string {
	// Substituir MathRand.Seed por um gerador local
	r := MathRand.New(MathRand.NewSource(time.Now().UnixNano()))
	randNum := r.Intn(max-min+1) + min // Gerar número aleatório usando o gerador local
	randStr := strconv.Itoa(randNum)
	return randStr
}

func RandInt(min int, max int) int {
	// Substituir MathRand.Seed por um gerador local
	r := MathRand.New(MathRand.NewSource(time.Now().UnixNano()))
	randNum := r.Intn(max-min+1) + min // Gerar número aleatório usando o gerador local

	return randNum
}

func Filter(strings []string, f func(string) bool) []string {
	var result []string
	for _, s := range strings {
		if f(s) {
			result = append(result, s)
		}
	}
	return result
}

func GenDados() (gjson.Result, error) {

	client := &http.Client{
		Timeout: time.Duration(10) * time.Second,
	}

	var data = strings.NewReader(`acao=gerar_pessoa&sexo=I&pontuacao=N&idade=0&cep_estado=&txt_qtde=1&cep_cidade=`)
	req, err := http.NewRequest("POST", "https://www.4devs.com.br/ferramentas_online.php", data)
	if err != nil {
		return gjson.Result{}, err
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")

	var resp *http.Response
	err = retry.Do(
		func() error {
			var err error
			resp, err = client.Do(req)
			return err
		},
		retry.Attempts(3),
		retry.OnRetry(func(n uint, err error) {
			fmt.Println(err.Error())
		}),
	)

	if err != nil {
		return gjson.Result{}, err
	}
	defer resp.Body.Close()

	// Capturando o retorno da request em Bytes e transformando em String
	bodyByte, err := io.ReadAll(resp.Body)
	if err != nil {
		return gjson.Result{}, err
	}

	return gjson.ParseBytes(bodyByte), nil
}

func GenDadosRnd(country string) (gjson.Result, error) {

	client := &http.Client{
		Timeout: time.Duration(10) * time.Second,
	}

	ip := GenIp()

	req, err := http.NewRequest("GET", "http://104.236.244.131/api/1.4?nat="+country, nil)
	// req, err := http.NewRequest("GET", "https://randomuser.me/api/1.4?nat="+country, nil)

	req.Header.Add("CF-Connecting-IP", fmt.Sprintf("%s", ip))
	req.Header.Add("X-Forwarded-For", fmt.Sprintf("%s", ip))
	req.Header.Add("X-Real-IP", fmt.Sprintf("%s", ip))
	req.Header.Add("X-True-Client-IP", fmt.Sprintf("%s", ip))
	if err != nil {
		return gjson.Result{}, err
	}

	var resp *http.Response
	err = retry.Do(
		func() error {
			var err error
			resp, err = client.Do(req)
			return err
		},
		retry.Attempts(3),
		retry.OnRetry(func(n uint, err error) {
			fmt.Println(err.Error())
		}),
	)

	if err != nil {
		return gjson.Result{}, err
	}
	defer resp.Body.Close()

	// Capturando o retorno da request em Bytes e transformando em String
	bodyByte, err := io.ReadAll(resp.Body)
	if err != nil {
		return gjson.Result{}, err
	}

	return gjson.GetBytes(bodyByte, "results.0"), nil
}

func ReverseArray(arr []string) []string {
	for i, j := 0, len(arr)-1; i < j; i, j = i+1, j-1 {
		arr[i], arr[j] = arr[j], arr[i]
	}
	return arr
}

func FixJSON(jsonStr string) string {
	re := regexp.MustCompile(`(?m)(?P<key>\b[a-zA-Z_][a-zA-Z0-9_]*\b)\s*:`)
	return re.ReplaceAllString(jsonStr, `"${key}":`)
}

func GetCookieByName(cookie []*http1.Cookie, name string) string {
	cookieLen := len(cookie)
	result := ""
	for i := 0; i < cookieLen; i++ {
		if cookie[i].Name == name {
			result = cookie[i].Value
		}
	}
	return result
}

func Find(arr []string, f func(interface{}) bool) string {
	for _, v := range arr {
		if f(v) {
			return v
		}
	}
	return ""
}

func JoinMaps(slice []map[string]string, separator string) string {
	var result []string
	for _, m := range slice {
		for key, value := range m {
			result = append(result, fmt.Sprintf("%s: %s", key, value))
		}
	}
	return strings.Join(result, separator)
}

func SaveData(filename string, text string) error {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	defer f.Close()

	if _, err = f.WriteString(text); err != nil {
		return err
	}
	return nil
}

func WriteData(filename string, text string) error {

	err := os.WriteFile(filename, []byte(text), 0666)
	if err != nil {
		return err
	}

	return nil
}

// Função para validar e formatar CPF
func FormatCPF(cpf string) (string, error) {
	// Remover caracteres não numéricos
	cpf = regexp.MustCompile(`[^\d]`).ReplaceAllString(cpf, "")

	// Verificar se o CPF possui 11 dígitos
	if len(cpf) != 11 {
		return "", fmt.Errorf("CPF inválido, deve conter 11 dígitos")
	}

	// Formatando o CPF com pontuação
	formattedCPF := fmt.Sprintf("%s.%s.%s-%s", cpf[0:3], cpf[3:6], cpf[6:9], cpf[9:11])

	return formattedCPF, nil
}

// Função para validar e formatar CNPJ
func FormatCNPJ(cnpj string) (string, error) {
	// Remover caracteres não numéricos
	cnpj = regexp.MustCompile(`[^\d]`).ReplaceAllString(cnpj, "")

	// Verificar se o CNPJ possui 14 dígitos
	if len(cnpj) != 14 {
		return "", fmt.Errorf("CNPJ inválido, deve conter 14 dígitos")
	}

	// Formatando o CNPJ com pontuação
	formattedCNPJ := fmt.Sprintf("%s.%s.%s/%s-%s", cnpj[0:2], cnpj[2:5], cnpj[5:8], cnpj[8:12], cnpj[12:14])

	return formattedCNPJ, nil
}

func IsAlphanum(data string) bool {
	hasLetter := regexp.MustCompile(`[a-zA-Z]`).MatchString(data)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(data)
	return hasLetter && hasNumber
}

func IsNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

func ReplaceNumericChars(s string) string {
	result := strings.Builder{}

	for _, char := range s {
		if IsNumeric(string(char)) {
			result.WriteString(strconv.Itoa(MathRand.Intn(10)))
		} else {
			result.WriteRune(char)
		}
	}

	return result.String()
}

// ENCRYPT & DECRYPT

func RsaEncrypt(ciphertext []byte, key string) ([]byte, error) {
	block, _ := pem.Decode([]byte("-----BEGIN PUBLIC KEY-----\n" + key + "\n-----END PUBLIC KEY-----"))
	if block == nil {
		return nil, errors.New("public key error!")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptPKCS1v15(rand.Reader, pub.(*rsa.PublicKey), ciphertext)
}

func RsaDecrypt(ciphertext []byte, key string) ([]byte, error) {
	block, _ := pem.Decode([]byte("-----BEGIN PRIVATE KEY-----\n" + key + "\n-----END PRIVATE KEY-----"))
	if block == nil {
		return nil, errors.New("private key error!")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}

// encryptAES encrypts plaintext using AES/ECB/PKCS5Padding and returns the result in Base64.
func EncryptAES_ECB(plaintext, base64Key string) (string, error) {
	// Decode the Base64 key
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return "", fmt.Errorf("invalid base64 key: %w", err)
	}

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// AES block size
	blockSize := block.BlockSize()

	// Apply PKCS5 padding
	paddedText := padPKCS7([]byte(plaintext), blockSize)

	// Encrypt in ECB mode
	ciphertext := make([]byte, len(paddedText))
	for i := 0; i < len(paddedText); i += blockSize {
		block.Encrypt(ciphertext[i:i+blockSize], paddedText[i:i+blockSize])
	}

	// Encode the result in Base64
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func AESEncrypt(src string, key []byte, ivBytes []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("key error1", err)
	}
	if src == "" {
		fmt.Println("plain content empty")
	}
	ecb := cipher.NewCBCEncrypter(block, ivBytes)
	content := []byte(src)
	content = PKCS5Padding(content, block.BlockSize())
	crypted := make([]byte, len(content))
	ecb.CryptBlocks(crypted, content)
	return crypted
}

func AESEncryptPKCS7(src string, key []byte, ivBytes []byte) []byte {
	// Criar um bloco de cifra com a chave fornecida
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("Erro ao criar bloco de cifra:", err)
		return nil
	}

	// Criar um cifrador AES em modo CBC com a chave e o IV fornecidos
	ecb := cipher.NewCBCEncrypter(block, ivBytes)

	// Converter a string de origem para bytes
	content := []byte(src)

	// Adicionar preenchimento PKCS7 ao conteúdo
	content = padPKCS7(content, block.BlockSize())

	// Criar um slice de bytes para conter o texto cifrado
	crypted := make([]byte, len(content))

	// Criptografar o conteúdo
	ecb.CryptBlocks(crypted, content)

	return crypted
}

func AESEncryptPKCS7_B64(text, key, iv string) (string, error) {
	// Converte texto, chave e IV para bytes
	plainText := []byte(text)
	keyBytes := []byte(key)
	ivBytes := []byte(iv)

	// Cria um novo bloco AES
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("erro ao criar o bloco AES: %v", err)
	}

	// Aplica PKCS7 padding
	plainText = padPKCS7(plainText, block.BlockSize())

	// Cria o modo CBC
	ciphertext := make([]byte, len(plainText))
	mode := cipher.NewCBCEncrypter(block, ivBytes)

	// Criptografa o texto
	mode.CryptBlocks(ciphertext, plainText)

	// Retorna o resultado como uma string Base64
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func AESDecrypt(crypt []byte, key []byte, ivBytes []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		// fmt.Println("key error1", err)
		return []byte("key error: " + err.Error())
	}
	if len(crypt) == 0 {
		// fmt.Println("plain content empty")
		return []byte("plain content empty")
	}
	ecb := cipher.NewCBCDecrypter(block, ivBytes)
	decrypted := make([]byte, len(crypt))
	ecb.CryptBlocks(decrypted, crypt)
	return PKCS5Trimming(decrypted)
}

// Função para remover PKCS7 padding
func pkcs7Unpadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("dados inválidos para remoção de padding")
	}
	padding := int(data[length-1])
	if padding > length || padding == 0 {
		return nil, fmt.Errorf("padding inválido")
	}
	return data[:length-padding], nil
}

// Função para descriptografar AES-CBC
func DecryptAES(encryptedBase64, key, iv string) (string, error) {
	// Converte entrada de texto criptografado, chave e IV para bytes
	encryptedData, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return "", fmt.Errorf("erro ao decodificar Base64: %v", err)
	}
	keyBytes := []byte(key)
	ivBytes := []byte(iv)

	// Cria um novo bloco AES
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("erro ao criar o bloco AES: %v", err)
	}

	// Verifica se o comprimento dos dados é múltiplo do tamanho do bloco
	if len(encryptedData)%aes.BlockSize != 0 {
		return "", fmt.Errorf("dados criptografados não são múltiplos do tamanho do bloco")
	}

	// Configura o modo CBC
	decryptedData := make([]byte, len(encryptedData))
	mode := cipher.NewCBCDecrypter(block, ivBytes)

	// Descriptografa os dados
	mode.CryptBlocks(decryptedData, encryptedData)

	// Remove o padding PKCS7
	decryptedData, err = pkcs7Unpadding(decryptedData)
	if err != nil {
		return "", fmt.Errorf("erro ao remover padding: %v", err)
	}

	// Retorna os dados descriptografados como string
	return string(decryptedData), nil
}

func padPKCS7(src []byte, blockSize int) []byte {
	padLen := blockSize - len(src)%blockSize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(src, padding...)
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}

func CHECKSUM(stringToHash string) string {
	hash := sha1.New()
	hash.Write([]byte(stringToHash))
	hashedBytes := hash.Sum(nil)
	return hex.EncodeToString(hashedBytes)
}

// INTER
func DeviceId() string {
	// Substituir MathRand.Seed por um gerador local
	r := MathRand.New(MathRand.NewSource(time.Now().UnixNano()))
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)
	randNum := strconv.FormatFloat(r.Float64(), 'f', -1, 64)
	input := timestamp + randNum
	hash := sha256.Sum256([]byte(input))
	return base64.StdEncoding.EncodeToString(hash[:])
}

func GenerateMac() string {
	yHQXB6y := "0123456789ABCDEF"
	uD88nn0 := ""
	for BKxMMY := 0; BKxMMY < 12; BKxMMY++ {
		uD88nn0 += string(yHQXB6y[MathRand.Intn(len(yHQXB6y))])
		if BKxMMY%2 == 1 && BKxMMY < 11 {
			uD88nn0 += ":"
		}
	}
	return uD88nn0
}

func GetCertsAndSig() map[string]string {
	DaIJE0 := []map[string]string{
		{
			"certificate": "MIIC0DCCAbgCAQAwgYoxDjAMBgNVBAoTBUlCIFBGMRcwFQYKCZImiZPyLGQBGRYHU01HNzcwRjFJMEcGA1UECxNANTlmOTFiZjFmMzRlMDkwNmQ5ZTIxOWNkMWRkODliYjU2OGE4MWViNzk2NjY5YWMzNTAzNzJmM2IwOWJlOTZiMjEUMBIGA1UEAxMLMDQwODE0OTE2NzQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCuw3saBiJSxDq9c8VqBX32uPMyVDb0ALFkRpns9EwFN5oKBArNshdPXNQLwDtEY2PD7euCmTrZ-vMYz8pmSSzcScz61j9pKGlx8rjbTFeV1gnkA3KP7dF5-JLOEK_F0m-JZoNVuwlepb8GG72LU_PnnMlKt7Kw80sTKAwg8TXAQNEuudme32kCdLOGROKvQC1Z-6nE6Yu5pcnwiyeVwf44FtF0kpAwAjxDVPIOMChmOXuLqHFvnI5hwA5DfvS-nk_igSK7LCDiAid-RPTfLaMJ2qSkzzu08E4NgSphjeGvrA4B313n2BR7PG-5ysGkiCOtoH0Y_IyDjXF4iG6JOIwxAgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEANFIZsaRKVGueFrvjbZKh3Kww-Vv8In4e_CNaAGkZ_n1u7oNYojbu-RsH9eo89-nBG930YrBDkvM0guftQtz-lPpWKvwRemmw7MVg5E5IiYimtCDUx_xA0uCXsVwr_HiplkA5vYLatwbnmQMjqf9H-n198C1Wf1QiUzsQDyL34xFJgTVC5t8JLwJt8hmjo9SEdWaburNL7NcYr51za_liYYSSrYNzesaijJ7gELC80fT20Bxy-KD3cw0xM7ra9SKUi_fFmWxWDOR1LEQmj4XRfwJaIGxHoGfB8eDDMUkuKDfs2eyAIeeuzB0K4Dd2YReBJqbJf6LIaK_YkASnH4b5qw",
			"signature":   "137978f1c06f59cd05744" + "c04863af3f766eb4cdb38" + "7653616121af1348598dd" + "\x38",
		},
		{
			"certificate": "\x4d\x49\x49\x43\x30\x44\x43\x43\x41\x62\x67\x43\x41\x51\x41\x77\x67\x59\x6f\x78\x44\x6a\x41\x4d\x42\x67\x4e\x56\x42\x41\x6f\x54\x42\x55\x6c\x43\x49\x46\x42\x47\x4d\x52\x63\x77\x46\x51\x59\x4b\x43\x5a\x49\x6d\x69\x5a\x50\x79\x4c\x47\x51\x42\x47\x52\x59\x48\x55\x30\x31\x48\x4e\x7a\x63\x77\x52\x6a\x46\x4a\x4d\x45\x63\x47\x41\x31\x55\x45\x43\x78\x4e\x41\x4d\x57\x51\x33\x5a\x6d\x49\x31\x59\x7a\x52\x6a\x59\x57\x4a\x6c\x5a\x47\x51\x30\x4e\x6a\x45\x31\x5a\x54\x56\x6a\x5a\x6a\x6b\x32\x4e\x6d\x4a\x69\x4e\x57\x4a\x69\x4f\x54\x68\x6a\x5a\x44\x56\x6d\x4e\x32\x51\x77\x4f\x44\x6b\x79\x4d\x32\x45\x78\x4d\x47\x4e\x6c\x5a\x6a\x49\x31\x59\x6d\x46\x6c\x4e\x54\x45\x35\x59\x6d\x51\x33\x4e\x6d\x55\x77\x5a\x6a\x45\x55\x4d\x42\x49\x47\x41\x31\x55\x45\x41\x78\x4d\x4c\x4d\x44\x51\x77\x4f\x44\x45\x30\x4f\x54\x45\x32\x4e\x7a\x51\x77\x67\x67\x45\x69\x4d\x41\x30\x47\x43\x53\x71\x47\x53\x49\x62\x33\x44\x51\x45\x42\x41\x51\x55\x41\x41\x34\x49\x42\x44\x77\x41\x77\x67\x67\x45\x4b\x41\x6f\x49\x42\x41\x51\x44\x7a\x44\x33\x44\x4a\x4c\x74\x2d\x33\x4a\x30\x4c\x33\x32\x5f\x6e\x36\x45\x32\x5f\x61\x58\x74\x58\x6e\x4e\x31\x38\x46\x73\x5a\x37\x79\x45\x53\x63\x6a\x59\x2d\x30\x52\x6d\x53\x70\x32\x6b\x6d\x6d\x65\x65\x41\x54\x4c\x4a\x32\x73\x6d\x6b\x77\x79\x4e\x57\x33\x6a\x49\x50\x36\x4e\x42\x37\x33\x35\x42\x36\x54" + "7GIoliV1BwSXIc2ETfhGLXLCAqBj4Vsjvqr471QUToR1VWHjOLMO42Y1TcLez2t0LQrgjnJofthMSBHweSWygQVIlv0O-wIuVFFrujxqPHwjvmzmSHfZ85fVkm6cMlE3NRKglW9f4FTf3mnP0EgmFTbhFKM5vN5o5ssbOhhfDtI-nI7U2R7quyZj1dBaLBgpgSnd-J52IpRszC85zdfQ676svuT3hTpRidXMpHMl-3hBPDS2-RqKwUWm3vKJhHYJdgk_bvlVcrAgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAwMnvnf-Ui070R8rd3wvS" + "Q4U_K7LLoXt2EJFjgcXaS4oPNe1XNz8_e0jUrQhmYtI3DxSIK3xTZRrM5xamzgNflJj5bEsM9vv4mZBc1XlaYajk-NTrZAffmo_TNVpv86DJ7LZq9YEyxo2pkKvLYoXHvVs7tgy3mHv7Qnc4GOaxB69NGA76Vbm-5A5NmTQRDIjpZSxGsQBn5f9npCaX501BV9R5OUG8v5fasRDSMp4vMtdDtxTg5Babed4ag16Iae19y0TyZZGmq_R2O414GxkFPLEXz8wgGCbbvl0ozS1LqnVGlVbvFfwoCabbjUjt1j_khZ3uiySsnqH8uqnZKTaEyA",
			"signature":   "f9a0e592fc972f4ecbf7c6d0b05dfbb0a1bfa4632030ccf6cc3dc39e706724e5",
		},
		{
			"certificate": "\u004d\u0049\u0049\u0043\u0030\u0044\u0043\u0043\u0041\u0062\u0067\u0043\u0041\u0051\u0041\u0077\u0067\u0059\u006f\u0078\u0044\u006a\u0041\u004d\u0042\u0067\u004e\u0056\u0042\u0041\u006f\u0054\u0042\u0055\u006c\u0043\u0049\u0046\u0042\u0047\u004d\u0052\u0063\u0077\u0046\u0051\u0059\u004b\u0043\u005a\u0049\u006d\u0069\u005a\u0050\u0079\u004c\u0047\u0051\u0042\u0047\u0052\u0059\u0048\u0055\u0030\u0031\u0048\u004e\u007a\u0063\u0077\u0052\u006a\u0046\u004a\u004d\u0045\u0063\u0047\u0041\u0031\u0055\u0045\u0043\u0078\u004e\u0041\u005a\u0054\u0059\u0078\u005a\u0054\u0045\u0032\u004e\u0032\u004d\u0034\u0059\u0054\u005a\u0068\u004d\u007a\u0056\u006c\u004d\u006a\u0055\u0077\u004d\u0057\u0049\u0032\u004f\u0057\u005a\u006a\u004d\u007a\u004d\u0035\u005a\u0054\u0064\u0068\u004d\u006d\u0051\u0078\u005a\u0054\u006b\u0077\u0059\u0057\u0046\u006b\u004d\u0044\u004d\u0033\u004e\u0054\u006b\u007a\u0059\u007a\u0045\u007a\u0059\u006d\u0049\u007a\u0059\u006a\u004d\u0032\u004f\u0057\u0055\u0030\u004e\u0044\u0052\u0068\u004e\u0044\u004a\u0068\u0059\u0054\u0045\u0055\u004d\u0042\u0049\u0047\u0041\u0031\u0055\u0045\u0041\u0078\u004d\u004c\u004d\u0044\u0051\u0077\u004f\u0044\u0045\u0030\u004f\u0054\u0045\u0032\u004e\u007a\u0051\u0077\u0067\u0067\u0045\u0069\u004d\u0041\u0030\u0047\u0043\u0053\u0071\u0047\u0053\u0049\u0062\u0033\u0044\u0051\u0045\u0042\u0041\u0051\u0055\u0041\u0041\u0034\u0049\u0042\u0044\u0077\u0041\u0077\u0067\u0067\u0045\u004b\u0041\u006f\u0049\u0042\u0041\u0051\u0043\u0055\u0057\u006f\u0069\u0064\u0048\u0032\u0057\u0052\u0076\u0053\u0032\u0043\u0063\u0056\u0078\u0031\u0069\u0030\u0051\u0032\u0066\u004b\u0042\u006e\u0068\u004a\u0035\u0079\u0063\u0068\u0056\u006f\u004e\u0041\u0062\u0079\u0047\u0079\u0049\u005a\u006f\u0054\u0039\u0058\u004f\u0065\u007a\u0038\u0072\u0050\u0055\u0079\u004a\u0033\u0079\u0031\u0038\u0035\u0054\u0065\u0059\u0055\u0074\u0050\u0057\u0074\u004f\u0030\u0065\u0048\u0041\u0057\u004e\u0043\u0049\u006e\u0051\u0058\u0033\u0077\u006a\u0062\u0035\u0071\u0033\u004d\u005f\u007a\u0077\u0079\u0053\u0030\u0051\u004f\u0046\u0074\u0074\u0030\u0074\u0045\u0030\u0042\u0055\u0074\u004e\u0056\u006f\u0054\u0054\u0045\u0034\u007a\u004e\u005f\u0037\u0038\u005f\u0064\u0073\u006b\u0051\u005f\u0048\u0062\u0063\u0037\u0071\u006c\u0045\u0079\u0068\u005f\u0044\u004a\u0039\u006a\u0036\u0049\u0035\u0047\u0074\u005f\u0078\u0066\u006c\u0054\u0062\u0057\u0073\u0065\u004f\u002d\u0057\u0041\u0069\u0048\u006a\u0076\u004d\u0034\u0042\u0059\u004b\u0069\u0034\u0033\u0036\u0053\u0068\u0077\u0038\u0053\u0052\u0049\u004c\u006c\u0062\u0079\u0051\u0047\u0062\u0072\u004b\u0065\u0044\u0032\u0078\u006b\u006a\u0067\u0071\u0076\u0034\u0063\u005a\u0052\u0054\u0033\u0032\u006f\u004b\u0057\u0075\u004e\u0057\u0056\u0065\u0033\u0031\u0047\u0052\u0053\u0066\u006b\u0037\u007a\u006e\u0061\u0033\u0053\u0065\u0051\u0057\u0061\u002d\u0070\u0042\u0044\u0068\u0077\u004a\u006c\u0058\u0033\u004a\u006b\u0054\u006c\u0042\u0068\u006e\u004b\u0073\u0037\u0053\u0033\u0066\u0035\u0062\u005f\u006d\u0078\u0079\u004f\u0032\u0066\u0059\u0059\u0063\u005f\u0058\u0075\u006e\u0046\u004e\u0065\u0077\u0045\u0071\u0063\u0077\u0059\u0052\u0058\u0070\u0035\u0070\u0068\u0064\u0050\u004b\u002d\u0043\u0043\u0070\u0074\u0074\u0052\u0038\u0074\u004d\u0044\u005f\u0074\u0078\u0071\u0065\u0032\u0074\u006d\u0062\u0053\u0039\u0051\u0032\u0063\u004d\u0051\u0030\u0054\u0047\u0037\u0032\u0053\u0049\u0041\u0048\u0044\u0056\u004a\u0031\u0061\u0061\u0051\u0061\u0036\u0044\u006a\u0050\u006d\u0064\u0062\u0051\u0061\u0055\u004e\u0064\u0071\u0062\u0031\u0041\u0067\u004d\u0042\u0041\u0041\u0047\u0067\u0041\u0044\u0041\u004e\u0042\u0067\u006b\u0071\u0068\u006b\u0069\u0047\u0039\u0077\u0030\u0042\u0041\u0051\u0073\u0046\u0041\u0041\u004f\u0043\u0041\u0051\u0045\u0041\u006b\u0044\u004c\u0052\u0054\u0079\u0053\u005a\u005a\u0043\u0071\u0046\u0065\u007a\u0041\u0052\u002d\u006b\u006a\u0035\u006f\u0051\u004c\u0079\u002d\u0069\u0037\u0046\u0053\u0054\u0073\u0059\u006f\u004d\u0074\u004a\u0062\u0050\u0077\u0079\u004b\u0067\u0061\u0037\u0051\u0074\u005a\u006e\u0072\u0047\u004a\u0047\u0064\u0048\u0048\u0079\u0066\u0070\u006f\u0042\u0033\u0057\u0068\u0071\u0036\u0069\u0051\u006c\u0046\u0059\u0071\u0039\u006a\u0054\u007a\u0043\u0039\u0045\u006f\u0039\u0071\u0078\u0030\u0032\u0044\u0037\u0054\u0062\u006b\u004d\u0057\u0058\u0033\u006c\u0076\u006d\u006f\u0036\u0037\u0030\u0057\u0055\u0064\u004f\u0056\u0069\u0061\u0032\u006a\u006a\u005a\u0079\u0063\u0046\u005a\u004d\u006d\u002d\u0074\u0065\u0079\u0071\u004a\u0066\u0045\u005f\u006e\u0069\u0066\u006b\u004a\u0079\u006a\u006f\u0063\u004e\u006a\u0072\u0053\u0038\u004c\u005a\u0033\u0058\u0075\u006e\u0052\u0074\u0030\u0070\u0046\u0076\u0069\u0073\u0034\u0036\u0077\u006c\u0070\u0039\u0075\u006e\u006e\u0045\u0073\u0068\u0059\u0043\u005a\u0059\u0035\u0070\u0049\u0077\u0064\u004a\u0043\u0042\u0051\u0034\u006c\u0066\u006a\u0066\u0045\u0038\u004c\u0036\u0047\u004d\u0069\u0068\u0038\u004a\u0044\u0064\u0063\u0044\u0036\u0064\u0050\u0071\u0058\u006c\u0050\u0065\u0044\u0059\u0068\u002d\u0044\u0044\u0072\u0031\u0033\u0061\u006f\u0050\u0039\u004f\u0035\u004e\u0035\u006e\u0046\u004a\u0068\u0054\u006a\u0039\u0062\u0073\u0055\u0059\u0035\u0065\u0067\u0046\u0070\u006d\u004f\u0053\u0076\u0047\u0039\u0073\u0055\u0041\u0050\u0058\u005a\u0075\u0050\u0068\u0045\u0059\u005a\u004b\u0044\u0056\u0033\u0079\u0063\u0072\u0031\u0056\u006b\u004f\u0051\u0068\u004f\u0055\u0052\u0047\u0034\u0044\u0073\u0031\u0077\u0030\u0073\u0077\u0047\u0065\u0069\u0036\u0033\u0075\u006c\u0037\u0047\u0062\u006c\u0041\u0054\u005f\u004b\u004d\u005f\u0059\u004f\u0075\u006a\u0059\u0052\u006c\u0050\u0039\u004f\u004a\u0043\u0077\u0035\u0066\u0039\u006d\u0034\u004d\u0069\u0079\u0078\u005a\u0058\u006b\u0059\u0058\u0057\u0073\u0035\u0076\u0062\u0079\u006f\u0052\u0050\u0078\u007a\u004c\u0053\u0030\u0076\u0077",
			"signature":   "f037840e34d612b24b89221098fd7b417f24185c79d0e309dcad63adac4d6691",
		},
		{
			"certificate": "MIIC0DCCAbgCAQAwgYoxDjAMBgNVBAoTBUlCIFBGMRcwFQYKCZImiZPyLGQBGRYHU01HNzcwRjFJMEcGA1UECxNAMTFmNjZlNmI3MjQ1NjJiZjdmOTRjYjU1ZWYyN2VkNDk0NzZjNmI5OTU2ODQ0NGI2ZjJhMTA2OTNlMTg2YzRjNTEUMBIGA1UEAxMLMDQwODE0OTE2NzQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDcCE1vjUZaWDEnMZg-LgX35FqfsrZqUx_2WECQF7GmP6zf2uztEg5De2JqWilcx8tibSia0xF69nbtS_jpClNOfNwOYxIBTwWJ5AuBeuKsOPCpTfhV0SSG0ctkicARWJjk57QEjQ0ik-2V_TlJWa9SnlKVtq8LXOoGdPf327wa3huRsaTPsu5L7dfIjjglNOdXEIgyMhOX3UzhOaBFHoEGZlKKtvdLL7P5ktlw8ThXj2T_-BaOpxZAQdO7nfrSwkSQGassqoQYf2p6aCinv8ae7wB16P1Mir53yVIDVnPx7EWtBfY5uEx31-CL3K51BCsDPzfIBFdzqyTy9oc1Eb8FAgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAX0N0Tkq3rvgkPmVVkZpBxlHqCNyIdPUPsekdOGqjGseilj5xSGgM8duv2w9vV25kn0a-NdsV7P2oYbuqI5p_Q2xl5nu0cD5xLgSslo2_pzSiJx-Fq7VxyEhUEYfOBNQray_FRjnBWoj_Bek48yDu8IRnh9jANvfL5s48ukU2sjgZG-4wwX4GvKOC6SMmdd9xasvYWo_tZcOuQjRr3EkRp_4CTfXxcr1zoUHMWf5jIdwPQyb3L4JKd4qQWnS6FvQpSdVrc-PIRl0D8QmDVa7JaHqy3Tfg2V2Ey96KAVZF-OdYpwwYdDR0N6SQjdRS6MfVj04lqyj9a0lrbc0gRoimOQ",
			"signature":   "36c9befd15d92" + "d4966050d5982" + "39804d531dae2" + "a36b8fdfd1074" + "92f4168e2744",
		},
		{
			"certificate": "\u004d\u0049\u0049\u0043\u0030\u0044\u0043\u0043\u0041\u0062\u0067\u0043\u0041\u0051\u0041\u0077\u0067\u0059\u006f\u0078\u0044\u006a\u0041\u004d\u0042\u0067\u004e\u0056\u0042\u0041\u006f\u0054\u0042\u0055\u006c\u0043\u0049\u0046\u0042\u0047\u004d\u0052\u0063\u0077\u0046\u0051\u0059\u004b\u0043\u005a\u0049\u006d\u0069\u005a\u0050\u0079\u004c\u0047\u0051\u0042\u0047\u0052\u0059\u0048\u0055\u0030\u0031\u0048\u004e\u007a\u0063\u0077\u0052\u006a\u0046\u004a\u004d\u0045\u0063\u0047\u0041\u0031\u0055\u0045\u0043\u0078\u004e\u0041\u004f\u0054\u0067\u0031\u004d\u006d\u0059\u007a\u004e\u0054\u004a\u006c\u005a\u0044\u0059\u0078\u004d\u006a\u0063\u0030\u004d\u0057\u005a\u006a\u004d\u007a\u0059\u0078\u005a\u0054\u0059\u007a\u005a\u0057\u0051\u0033\u0059\u007a\u0052\u006c\u004e\u0032\u0046\u006a\u004f\u0054\u0067\u0032\u004d\u0054\u0064\u006d\u004e\u006d\u0051\u0035\u004f\u0044\u0063\u0034\u004e\u0044\u0046\u0069\u005a\u0044\u0049\u0031\u0059\u007a\u0055\u0032\u0059\u0054\u0045\u0077\u0059\u0057\u004e\u006b\u004e\u0057\u0056\u0069\u0059\u007a\u0045\u0055\u004d\u0042\u0049\u0047\u0041\u0031\u0055\u0045\u0041\u0078\u004d\u004c\u004d\u0044\u0051\u0077\u004f\u0044\u0045\u0030\u004f\u0054\u0045\u0032\u004e\u007a\u0051\u0077\u0067\u0067\u0045\u0069\u004d\u0041\u0030\u0047\u0043\u0053\u0071\u0047\u0053\u0049\u0062\u0033\u0044\u0051\u0045\u0042\u0041\u0051\u0055\u0041\u0041\u0034\u0049\u0042\u0044\u0077\u0041\u0077\u0067\u0067\u0045\u004b\u0041\u006f\u0049\u0042\u0041\u0051\u0044\u0042\u0047\u0058\u0079\u0048\u0075\u0045\u0068\u0063\u0066\u0033\u0030\u004e\u0037\u0049\u004d\u0077\u0063\u0073\u0056\u0057\u0074\u0057\u006e\u0061\u005f\u0052\u0077\u0052\u0071\u0070\u0063\u0031\u0056\u006d\u0032\u005a\u0062\u0070\u0043\u0071\u0041\u0049\u007a\u0057\u006b\u0053\u0057\u0054\u004f\u0037\u0056\u0043\u005f\u0038\u0035\u004e\u006a\u0043\u0036\u0038\u0059\u0072\u0077\u0062\u0050\u0042\u0069\u0051\u0050\u0066\u0059\u0078\u0062\u0031\u0052\u006b\u006b\u0079\u0037\u004a\u0051\u0076\u004a\u0030\u0074\u0030\u0050\u0066\u0072\u0070\u0056\u004d\u0051\u006e\u0072\u0031\u0033\u0059\u005f\u0042\u0057\u006f\u0046\u0033\u0073\u0051\u0036\u0062\u0044\u006a\u0056\u0051\u0031\u0050\u006b\u0063\u0050\u0051\u0061\u0073\u0079\u0057\u004d\u0039\u0036\u0055\u0046\u0036\u0069\u0044\u006b\u0037\u004c\u0052\u004a\u004c\u0049\u004d\u0034\u0037\u0036\u0075\u0073\u0064\u004b\u0033\u006d\u0039\u0067\u0048\u006a\u006b\u0046\u0049\u0053\u0044\u002d\u0076\u0058\u0039\u0065\u0045\u0054\u0047\u0048\u0061\u006f\u0031\u0033\u0035\u0031\u0065\u0039\u0034\u0036\u004b\u0062\u0070\u005a\u0035\u0062\u0032\u0033\u0061\u006c\u0055\u0033\u0059\u0034\u0037\u0033\u004c\u006f\u004c\u006e\u0043\u004e\u0049\u0071\u0033\u0034\u0051\u004a\u0035\u0047\u0061\u0076\u0046\u004b\u0061\u004e\u0062\u0051\u0057\u0074\u0054\u0061\u006f\u0042\u0076\u0054\u004a\u0053\u0079\u0045\u0072\u0069\u004b\u0070\u0059\u0045\u0039\u005f\u0037\u006e\u0038\u002d\u0045\u0045\u0071\u0067\u0075\u005f\u006a\u0036\u004c\u0066\u0033\u0054\u0062\u0033\u004f\u0063\u0037\u0051\u005a\u0055\u004e\u0039\u0066\u0070\u0033\u0075\u0058\u0042\u005f\u0045\u004e\u0035\u0058\u0075\u0069\u0056\u0033\u0075\u004d\u0047\u0075\u0051\u004a\u005a\u0064\u0055\u0049\u0038\u0032\u0031\u006c\u0041\u0031\u005f\u0033\u004e\u0069\u0053\u0047\u0076\u0068\u0067\u0075\u0063\u005a\u0074\u0036\u004b\u002d\u006d\u0073\u004a\u0077\u0070\u005a\u0052\u005a\u0072\u0057\u0036\u0079\u0054\u0037\u0065\u0037\u0047\u006e\u007a\u0078\u0033\u0048\u005f\u004e\u0077\u0064\u0059\u0067\u0052\u007a\u0058\u0074\u0063\u0078\u0041\u0067\u004d\u0042\u0041\u0041\u0047\u0067\u0041\u0044\u0041\u004e\u0042\u0067\u006b\u0071\u0068\u006b\u0069\u0047\u0039\u0077\u0030\u0042\u0041\u0051\u0073\u0046\u0041\u0041\u004f\u0043\u0041\u0051\u0045\u0041\u0072\u0077\u0030\u0032\u0066\u0072\u0067\u0054\u0035\u006a\u004d\u0038\u0061\u005a\u004f\u0072\u0055\u0067\u0052\u0042\u0059\u0039\u0079\u0051\u0051\u004b\u0043\u0046\u006e\u0051\u0044\u0064\u004b\u007a\u0037\u0066\u0035\u0070\u0031\u0067\u0037\u0059\u0037\u0035\u004f\u0058\u004d\u0049\u0034\u0048\u0033\u0076\u0037\u006e\u0068\u0051\u0076\u0066\u0053\u0072\u0049\u004c\u0039\u0046\u005a\u0055\u0067\u0032\u0042\u004e\u0063\u006f\u0064\u0059\u0041\u0036\u0077\u0068\u0078\u0079\u0066\u006c\u0050\u0055\u0056\u006b\u0033\u0075\u0079\u004c\u004b\u0052\u0037\u0048\u004d\u0069\u0048\u004c\u0061\u004f\u0057\u0048\u0037\u0044\u0071\u006a\u0075\u0030\u006d\u0067\u0039\u0065\u004c\u0074\u002d\u006a\u0047\u0059\u0075\u004e\u0032\u0030\u0039\u0051\u0069\u0042\u0069\u0039\u0038\u005a\u0030\u0063\u0048\u0059\u0032\u0059\u005f\u0038\u0052\u0051\u006e\u002d\u006d\u006f\u006b\u0042\u0061\u0072\u004d\u0038\u0067\u0043\u0049\u0051\u0074\u0030\u0070\u002d\u0066\u0078\u004c\u002d\u0039\u0042\u0076\u0030\u007a\u0057\u0053\u0058\u0059\u0039\u0070\u0037\u0075\u0037\u006c\u005f\u006b\u0071\u0070\u0074\u0052\u005f\u0079\u004b\u0038\u0050\u0035\u0063\u0079\u0047\u0032\u0058\u004f\u004a\u0076\u005f\u0055\u0076\u0075\u0042\u0074\u0039\u0072\u0071\u0046\u0034\u004c\u0042\u004e\u004e\u0053\u0074\u0054\u0037\u0038\u0075\u0032\u0076\u0047\u0062\u0041\u006d\u0067\u0076\u0034\u0065\u004b\u006d\u0039\u0038\u0030\u0045\u004d\u0064\u0071\u0057\u0077\u0035\u0053\u006a\u0079\u006c\u0066\u0049\u0061\u0064\u004d\u007a\u0058\u0068\u0047\u0047\u0043\u0032\u0030\u0064\u0032\u0078\u0034\u0074\u0063\u0057\u004a\u006c\u0046\u0070\u005f\u0044\u0061\u0073\u0062\u006a\u0058\u0039\u005a\u006d\u0059\u0049\u0066\u0039\u0051\u0072\u004c\u0052\u0067\u0043\u0077\u0047\u0071\u0044\u006c\u0037\u006e\u0045\u0036\u007a\u0052\u002d\u0045\u004d\u0046\u002d\u0077\u0039\u004b\u0073\u0045\u0032\u0062\u004a\u0045\u004e\u0071\u0033\u006e\u0072\u006f\u004a\u0034\u006a\u0069\u0030\u004d\u0037\u0067\u0069\u006a\u0056\u0043\u0035\u0058\u004e\u0056\u006e\u0062\u006e\u0043\u0072\u0038\u0051",
			"signature":   "\x36\x32\x37\x34\x63\x36\x33\x61\x33\x65\x34\x38\x32\x37\x32\x62\x64\x30\x32\x33\x37\x62\x62\x63\x35\x35\x30\x30\x61\x38\x62\x38\x66\x62\x65\x34\x36\x63\x63\x64\x37\x61\x32\x61\x62\x62\x61\x37\x63\x66\x61\x33\x32\x64\x61\x32\x35\x38\x39\x31\x63\x30\x61\x66",
		},
		{
			"certificate": "MIIC0DCCAbgCAQAwgYoxDjAMBgNVBAoTBUlCIFBGMRcwFQYKCZImiZPyLGQBGRYHU01HNzcwRjFJMEcGA1UECxNAMWFiNjZhNWYxYmNlOTk4YTA1ODExYTI2ZGQwNzBhZTk5MjM2YjRhMzA2OTQ2Mzc2NjJiMmM0NjExOTcyYmY5MjEUMBIGA1UEAxMLMDQwODE0OTE2NzQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC-8w_5pJjxvXtXgxwY65esm5nvQfvVnplL_tBVSanSOYxfHWPNtyonbSzflo4ZxhtLGwgYcpqzWmkv-Qkzsm0wz97s3FvQDPE5DFMhoLYaN55ruCPwAoa1k_nayMykgl1e3rDXdNLm_2xNf6qGOIaNPqE4smkks-YFzvJM3o6V8TbclYrsEJPVMidXLW6HnZpYDn-UkJmh2uk0JBDDQR2oLjCaG_xOtImxLmtyMObaTutsx9zCxiweBHFZ8Q41fEneWOo2R3339HK-efeDv0Zpw2sdORvTW-0DzeK-owETJ1L1oITzgO1HYrHx3_WAhfV853lnq4oFnIcw7WiLqoopAgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAq8io9qzMaZxba3PYHG3n8y1e8u-zC9J294wziUzuK5TraNdHBGOgmwmpjyLA8P6f6VmEDpYQn67koBgHEGBI7yKwTqpEG9OnQMNPR0UaJfBkCPYuJSTFATJMY4OuliqvEZNPTrq8hQLb44PuqtBce6fh6oa_-vSRvb_Bg-QZH1zwXmMQfJfu_yi2hEYc2XBPoVRbOlUzglUT-qxUGEdT9LGMPaS1VFOU-dRrTQ1svkLk6ZvtF0hdUQvvrlXYfOO0zuTqSXnn0h_Opo5AD8LUVKxOyKlyDNO8XzK5OIkZkZOS7exdfvXJ4eGUTeM30nOkoyGbn3LWyJuSNnjR9pJ7Pw",
			"signature":   "c1fcc67ca8b19a7421fa93ab3afe46f0eefb2f33adc666c470dbcd4e1e1feb58",
		},
		{
			"certificate": "MIIC0DCCAbgCAQAwgYoxDjAMBgNVBAoTBUlCIFBGMRcwFQYKCZImiZPyLGQBGRYHU01HNzcwRjFJMEcGA1UECxNAN2NjMTZkZmYwMjQ5MWM1YmViYWZhNjljYjBhMzJjMTgyOTY0ZWI5MDcxZDc4MmEzZDQ5M2I4M" + "WNhMGZjNDczMTEUMBIGA1UEAxMLMDQwODE0OTE2NzQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDlO_gcKPCcNC8HKhsGE78LKvod23pBgjDEAxmclJrMtlRSQ4Zj1E3TOLImlsOo8S8v1J9byPw2J5" + "yOteIBFATkXhMFeeCpqt05EKhQgjRhylaGaOG0fzmmMqofcqJFTS5v8or6bT4ErvggrADkxnXzV7UnfEsAkdRCw9sH7WnCmMnAz-a1mEiB7MurNfirY_bujfxI9f_33JIkLGKWS9dUEguonOrjXSjVpT_ZoCx1sS2" + "vUkjTYqR_Y1De5XrI_tBFPZlM3z0LuvURxzkqJxJMBQCG6eL-qGxq69SdpJnoRi_0Bu_ePLDv_VQaF2JK1Us6tx3-_F2eJKs0KFXOFu-hAgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAD_0fr4R5cDrdsha_gLAU" + "VIV6gKULn4LKve6gDrXIZoXY2eKh6w7FDqTNc-4MBoAPvnScEMyAz9ZlVYnVgn29wYICQ6y3N6iZ6dYwLAutMtNBSz8NjwGBr7g3jXaMcTmHvrvdiE2xKWnvrRRZzdvOGYkAeiLl6rmhbOWDSmlyqBYM5G-OhBxyK" + "v7cPb2Ye5Ebho4tCU0MBVnUCncp29QvGc_-NgTEuAsWzSBGaxdBq2iiPrzXKesS8IXTqaPXfgNhX0RSIfz2TbgNTjCpIk8Flsxq7bWOIrC_9y3eVB3u_XxZarlSIYZCjtgXVmlrnQSwXFF8WspJ8ihQre2E1_AcOQ",
			"signature":   "e563c5840d3de63653223" + "\x36\x33\x34\x31\x64\x37\x66\x39\x36\x66\x32\x61\x62\x33\x39\x66\x39\x37\x33\x37\x38" + "791ce08dae4b01ded0f2a" + "\x35",
		},
		{
			"certificate": "MIIC0DCCAbgCAQAwgYoxDjAMBgNVBAoTBUlCIFBGMRcwFQYKCZImiZPyLGQBGRYHU01HNzcwRjFJMEcGA1UECxNAOTE3NTI5Zjg0NjI1MjcxM2E1Yjc3ZDE2YjFjYWY3MzFmZDAzODlkZTRkOGE3MWY1MTNhMDMxOWQzYjhiZGQ3ZjEUMBIGA1UEAxMLMDQwO" + "DE0OTE2NzQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDYt0pn9WzyH6sHIAmmlcp8776fXpcMSe_StB3LHUEPAjD89t1yrTE67rwpRwpeH_PrwRTW-gBx0zqxYgsgenbbZfSQxjAG91E7H3J5FF9M-0jj2f-B-m1aSC74a7E6yC4XfoeXc9cTZR" + "\u006a\u0051\u006c\u004c\u0064\u004b\u006b\u0047\u0034\u0063\u0073\u006e\u0058\u0054\u0031\u0070\u0072\u0067\u0035\u0033\u007a\u004a\u007a\u0075\u0067\u0039\u007a\u0066\u0032\u0078\u0048\u0033\u004f\u005a\u0037\u007a\u006a\u0061\u0066\u0034\u0067\u0079\u0070\u0032\u0048\u0063\u004c\u006f\u0074\u0074\u004c\u006b\u0054\u0057\u004e\u0050\u0072\u0041\u0048\u0032\u0035\u0054\u0067\u0079\u0061\u0046\u0054\u006f\u006f\u0073\u006c\u0062\u004a\u0063\u0072\u0032\u0032\u0055\u0041\u0057\u004e\u0044\u0066\u0035\u0063\u0044\u0046\u0035\u0042\u002d\u0045\u004d\u0039\u0076\u0068\u0058\u0079\u005f\u0069\u0064\u006d\u0077\u0045\u0053\u0031\u0072\u0036\u0052\u0042\u0051\u004a\u0056\u0041\u0058\u006b\u0077\u0034\u0039\u004e\u0046\u005a\u004c\u004c\u0043\u0031\u006e\u0065\u0044\u0041\u004d\u0033\u006f\u0065\u0075\u006b\u0078\u004e\u0036\u0077\u004d\u005f\u006c\u0063\u0047\u0035\u0079\u0075\u0044\u0066\u006b\u006d\u0039\u006f\u0066\u0072\u0065\u0067\u0032\u0058\u004b\u006d\u005f\u0036\u0076\u006c\u0045\u0047\u0057\u006a\u0038\u0033\u0050\u0055\u0042\u0052\u0061\u006e\u0039\u0056\u0041\u0061\u004d\u0051\u004c\u0050\u0073\u002d\u0062\u0069\u0057\u0066\u0054\u006b" + "hNo9IN2tjAgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAKc4A64XJnb0tTM7TZ849Vp_X6Yw3DIUSUnendhIf5CR4mEVWkWw-BuZQZilF7nwopqtQEpp51Jn_XhUQHeQJNjsW65uckjpP5mxpbN0usHYhC1Gwxf2qSImObjCy4uI6UauLpc4MG_7GOU3NemOv" + "\x39\x30\x56\x4f\x58\x59\x6d\x6e\x34\x4b\x4f\x54\x61\x79\x6b\x6c\x5a\x68\x79\x37\x55\x41\x69\x56\x6d\x6e\x70\x42\x7a\x67\x73\x50\x35\x4e\x76\x75\x54\x79\x77\x43\x55\x6f\x4f\x41\x74\x34\x5f\x52\x30\x57\x73\x70\x6b\x35\x5f\x31\x4d\x67\x72\x72\x62\x4f\x55\x30\x6e\x77\x75\x36\x2d\x79\x4e\x78\x52\x78\x48\x45\x70\x4b\x41\x6a\x70\x6e\x78\x38\x31\x66\x54\x55\x44\x37\x70\x72\x4d\x4b\x4b\x31\x67\x31\x73\x4f\x38\x54\x4d\x53\x6c\x31\x56\x6a\x61\x67\x50\x4b\x4c\x50\x76\x6c\x30\x63\x4b\x79\x55\x79\x73\x6d\x77\x47\x79\x77\x52\x71\x73\x77\x55\x54\x61\x71\x51\x69\x71\x33\x54\x78\x61\x62\x48\x4c\x64\x63\x48\x78\x70\x4a\x42\x78\x4c\x6d\x68\x32\x39\x68\x4f\x37\x45\x44\x46\x69\x4f\x52\x49\x49\x44\x58\x66\x62\x35\x6b\x4e\x4d\x49\x6d\x42\x7a\x59\x6f\x32\x41\x4d\x58\x32\x2d\x38\x47\x57" + "\x67",
			"signature":   "757237080d3f1b7a097609f943c7a8e3f1f7558f46639c80aa3f7e7669b92581",
		},
		{
			"certificate": "\u004d\u0049\u0049\u0043\u0030\u0044\u0043\u0043\u0041\u0062\u0067\u0043\u0041\u0051\u0041\u0077\u0067\u0059\u006f\u0078\u0044\u006a\u0041\u004d\u0042\u0067\u004e\u0056\u0042\u0041\u006f\u0054\u0042\u0055\u006c\u0043\u0049\u0046\u0042\u0047\u004d\u0052\u0063\u0077\u0046\u0051\u0059\u004b\u0043\u005a\u0049\u006d\u0069\u005a\u0050\u0079\u004c\u0047\u0051\u0042\u0047\u0052\u0059\u0048\u0055\u0030\u0031\u0048\u004e\u007a\u0063\u0077\u0052\u006a\u0046\u004a\u004d\u0045\u0063\u0047\u0041\u0031\u0055\u0045\u0043\u0078\u004e\u0041\u0059\u0032\u0059\u0078\u005a\u0054\u0063\u007a\u004d\u007a\u0046\u006d\u004e\u006a\u0046\u006a\u0059\u007a\u005a\u006d\u004e\u0054\u0051\u0030\u005a\u0054\u0042\u006d\u004d\u0054\u0059\u0077\u004d\u006a\u0068\u0068\u004d\u006a\u0042\u006b\u004f\u0057\u0056\u006b\u004e\u006d\u004d\u0031\u004f\u0057\u0045\u0078\u004e\u0044\u004d\u0030\u004e\u0054\u0045\u0033\u0059\u006a\u0045\u0033\u004d\u006a\u0067\u0034\u005a\u0054\u0067\u0079\u004f\u0044\u0055\u0030\u0059\u0032\u0045\u007a\u0059\u0057\u004d\u0077\u005a\u006a\u0045\u0055\u004d\u0042\u0049\u0047\u0041\u0031\u0055\u0045\u0041\u0078\u004d\u004c\u004d\u0044\u0059\u0032\u004e\u0054\u0045\u0079\u004d\u007a\u0051\u0032\u004f\u0054\u0049\u0077\u0067\u0067\u0045\u0069\u004d\u0041\u0030\u0047\u0043\u0053\u0071\u0047\u0053\u0049\u0062\u0033\u0044\u0051\u0045\u0042\u0041\u0051\u0055\u0041\u0041\u0034\u0049\u0042\u0044\u0077\u0041\u0077\u0067\u0067\u0045\u004b\u0041\u006f\u0049\u0042\u0041\u0051\u0043\u0066\u006b\u0063\u0067\u0055\u0055\u0044\u0077\u0072\u0042\u0064\u0051\u0072\u0045\u0063\u0067\u0030\u0050\u0076\u0068\u0062\u0067\u0047\u002d\u0050\u0059\u0053\u0074\u006a\u0032\u0034\u0048\u0069\u0045\u0065\u0065\u005f\u0037\u0072\u0056\u0052\u004a\u0074\u0046\u0042\u006c\u002d\u0061\u0066\u0043\u0048\u0045\u0063\u0072\u004a\u0068\u0066\u006d\u002d\u0061\u0059\u0076\u0066\u006f\u0071\u0039\u006e\u0050\u0044\u0046\u0036\u0033\u0047\u0034\u004f\u0047\u0062\u005a\u0039\u005f\u0043\u0069\u0031\u005f\u0072\u0075\u0050\u0064\u0066\u0037\u0035\u0045\u0030\u0039\u0053\u005f\u0042\u0058\u006e\u0062\u004a\u004b\u0045\u0071\u0076\u006a\u0069\u0059\u0055\u0066\u0061\u0051\u0065\u004f\u0037\u0039\u0041\u006d\u0046\u004f\u0074\u006c\u0046\u0070\u0075\u0058\u0034\u0073\u0057\u0078\u004e\u0046\u0058\u0050\u004b\u0041\u0055\u0068\u0032\u0033\u0056\u0031\u004b\u0036\u0072\u0074\u004d\u004f\u0047\u0053\u0059\u0049\u0039\u0042\u0073\u0062\u0042\u0032\u0038\u0061\u006a\u0042\u004b\u0043\u0077\u0049\u004a\u0039\u004d\u0045\u006b\u0059\u0077\u0033\u0077\u0034\u0056\u0056\u0032\u0067\u0069\u006a\u0061\u0078\u007a\u0042\u0059\u0074\u0076\u0062\u0043\u0047\u0078\u0036\u0064\u002d\u0044\u0066\u0048\u0042\u0057\u0075\u0030\u0071\u0059\u006a\u0030\u0062\u0042\u006f\u004f\u0045\u0061\u0032\u0057\u0067\u0033\u0045\u0041\u0050\u0062\u0069\u0039\u0034\u006e\u0034\u0072\u0077\u0039\u0056\u002d\u0064\u0031\u0075\u0061\u0066\u0062\u0078\u0050\u0070\u0045\u004b\u006e\u0074\u002d\u0076\u0053\u0036\u0056\u0043\u002d\u0074\u006f\u0076\u007a\u004f\u0059\u0035\u0054\u005f\u0056\u0038\u006e\u0038\u0031\u0034\u0035\u0043\u006f\u004f\u0038\u0053\u0070\u004c\u005f\u0073\u0048\u0076\u0044\u0044\u0057\u0069\u0065\u006d\u0066\u005a\u0046\u0031\u0038\u0061\u005f\u006d\u006e\u0067\u006a\u005a\u006f\u0064\u004e\u0030\u005f\u0034\u0049\u0058\u0055\u0064\u0068\u0034\u0069\u004d\u0031\u0055\u0048\u0054\u004f\u0055\u0072\u004d\u0054\u0047\u004b\u0054\u0048\u0051\u0038\u0067\u006c\u0055\u005a\u0069\u006d\u0041\u006f\u006b\u0054\u0035\u0070\u0061\u006b\u006a\u0031\u0041\u0067\u004d\u0042\u0041\u0041\u0047\u0067\u0041\u0044\u0041\u004e\u0042\u0067\u006b\u0071\u0068\u006b\u0069\u0047\u0039\u0077\u0030\u0042\u0041\u0051\u0073\u0046\u0041\u0041\u004f\u0043\u0041\u0051\u0045\u0041\u006c\u0074\u0056\u0075\u004a\u0035\u0031\u004e\u0033\u0051\u0063\u0037\u0074\u0043\u0061\u0035\u005f\u0057\u006f\u0076\u0055\u0044\u0077\u004b\u0078\u0075\u004e\u0048\u004d\u0045\u0075\u0070\u0072\u0057\u0049\u0056\u006f\u0055\u0069\u0062\u004d\u0030\u004b\u0050\u004a\u0051\u0043\u0031\u0061\u0038\u0031\u006a\u004e\u0039\u0042\u004f\u0039\u0030\u006e\u006b\u007a\u0051\u0038\u0038\u0069\u0055\u0043\u004d\u0064\u0044\u006b\u006b\u0042\u0075\u0065\u0038\u006b\u002d\u0038\u004d\u006c\u0044\u0062\u0047\u0077\u0061\u0045\u0061\u0069\u0050\u0079\u0058\u006b\u0067\u0045\u0063\u0048\u0031\u0058\u0054\u0068\u004f\u004e\u0051\u0044\u006b\u0052\u0033\u004c\u0033\u0043\u006f\u0037\u004f\u0048\u0065\u0049\u0056\u004e\u0056\u0033\u0061\u0062\u0044\u0047\u006b\u0067\u0042\u005a\u0055\u0033\u005a\u005a\u0072\u0033\u006a\u0079\u0077\u0035\u0052\u0079\u0034\u0066\u0045\u0038\u006b\u0066\u004d\u006a\u0058\u006f\u0071\u004a\u0048\u004b\u0067\u0057\u0059\u0075\u0053\u006a\u0057\u0059\u0079\u0045\u0071\u0047\u006b\u0055\u0073\u002d\u0037\u0078\u0046\u006b\u0062\u0055\u004e\u006e\u006a\u0067\u0043\u004a\u0068\u0071\u0050\u004e\u0068\u0035\u0066\u0045\u0058\u0064\u0056\u0033\u0034\u006d\u004b\u0036\u0055\u0035\u0058\u0042\u004a\u0061\u0061\u006e\u0056\u002d\u0059\u0051\u0067\u0035\u005f\u0062\u006f\u0076\u0036\u0077\u0049\u0049\u002d\u0044\u0063\u0059\u0050\u0067\u0065\u0036\u0079\u0063\u0054\u005a\u0042\u0034\u0059\u005f\u005a\u0049\u0049\u0076\u006b\u0046\u0073\u004d\u0042\u0059\u0070\u0055\u0051\u006a\u0068\u0073\u0064\u0041\u0076\u0041\u0064\u0074\u004c\u0036\u0047\u0034\u0073\u0077\u0033\u005a\u0057\u0077\u0048\u0039\u0069\u0063\u007a\u0035\u0075\u006e\u0055\u0053\u0048\u0056\u0039\u0057\u0072\u0078\u0070\u0072\u0051\u0050\u0079\u004c\u0047\u0066\u0044\u0065\u0037\u0057\u004e\u004b\u0047\u0063\u0047\u0046\u0051\u006f\u0061\u0041\u0064\u0050\u0078\u0050\u0072\u0056\u0046\u0034\u0078\u0039\u006c\u006b\u0055\u0047\u004b\u006d\u004f\u0053\u005f\u0043\u0038\u005a\u0045\u0043\u006d\u004b\u006a\u006e\u006d\u0056\u0030\u0061\u0042\u0055\u0051",
			"signature":   "10a80d6ba6e2e0310f4cf" + "\x31\x37\x64\x30\x38\x66\x61\x66\x62\x37\x31\x39\x63\x39\x36\x32\x64\x36\x62\x32\x64" + "af286a04d94266b221f7d" + "\u0066",
		},
		{
			"certificate": "\x4d\x49\x49\x43\x30\x44\x43\x43\x41\x62\x67\x43\x41\x51\x41\x77\x67\x59\x6f\x78\x44\x6a\x41\x4d\x42\x67\x4e\x56\x42\x41\x6f\x54\x42\x55\x6c\x43\x49\x46\x42\x47\x4d\x52\x63\x77\x46\x51\x59\x4b\x43\x5a\x49\x6d\x69\x5a\x50\x79\x4c\x47\x51\x42\x47\x52\x59\x48\x55\x30\x31\x48\x4e\x7a\x63\x77\x52\x6a\x46\x4a\x4d\x45\x63\x47\x41\x31\x55\x45\x43\x78\x4e\x41\x5a\x47\x55\x35\x59\x6a\x41\x33\x59\x32\x56\x69\x4e\x57\x4a\x6a\x4d\x6d\x4d\x78\x4f\x44\x6c\x6a\x4d\x7a\x59\x30\x4d\x6a\x49\x79\x4d\x6a\x49\x77\x59\x54\x4d\x30\x5a\x44\x42\x69\x5a\x47\x55\x30\x4d\x32\x49\x32\x59\x6a\x56\x68\x5a\x54\x6c\x69\x5a\x57\x49\x32\x59\x32\x4e\x6d\x4f\x44\x4e\x6d\x4d\x44\x55\x32\x5a\x54\x4a\x6d\x4d\x44\x5a\x6b\x59\x6a\x45\x55\x4d\x42\x49\x47\x41\x31\x55\x45\x41\x78\x4d\x4c\x4d\x44\x51\x77\x4f\x44\x45\x30\x4f\x54\x45\x32\x4e\x7a\x51\x77\x67\x67\x45\x69\x4d\x41\x30\x47\x43\x53\x71\x47\x53\x49\x62\x33\x44\x51\x45\x42\x41\x51\x55\x41\x41\x34\x49\x42\x44\x77\x41\x77\x67\x67\x45\x4b\x41\x6f\x49\x42\x41\x51\x44\x59\x39\x70\x45\x50\x35\x6f\x4e\x54\x66\x65\x47\x50\x6a\x49\x77\x78\x7a\x5f\x63\x79\x64\x72\x7a\x44\x46\x36\x59\x6b\x39\x62\x6e\x77\x4d\x37\x71\x65\x66\x79\x39\x4b\x6a\x56\x62\x4f\x71\x4a\x6a\x53\x47\x55\x45\x6b\x64\x70\x67\x35\x35\x55\x54\x32\x67\x66\x39\x59\x67\x77\x5f\x31\x59\x44\x56\x59\x6e\x31" + "zwQcNqmG8ZfUkD1xERjqw3Pn6Bqp2a0ebN_fA7LhsntGiRbDT9PdI-tX2lb0_5ttGypzeN_hwYxDgyNvttcqNv4XxVCG6NGQbFv5ZgjSsVHoYUJjSe3msRTJgC6istKZ4ikWFGes2zILcCaQyyhefjDfKRQJrROezbcndjDLgNpaqu-ER0EngVAPVYbuIR-A5zd3QQ9v4FwGmVhwyqJ5FLcyUnIdd-f58ywp5SNM-NYj_FBo0BGxID1XxxmADmiEaPA_xvv_rPAgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAbjQvHy2qbkN9VewXTSuA" + "dihSLoWSZyqL3o5QfieciE7jI6eRVa7CX1F9c1f27Im3NH7oKq7klbCVCkSB1cLkyVxrNt0GjSBJqnT1MWJ1znIHdelLc8gCkoT5yHFm9jbgW2Fl-FG4cpGJVd70W40l1invKC6S-QaCGw2DEezXXK7voVfhb9pnyCY4M9eeSfFPYfDygCGr2x6HdWu9T1idl3FrhjkxirIjWfZSzHuKwfIR_JZIP-sbn3OLYMG4Wno4fM26JNgoK4dciWuwvs0tLCHL9V8o5NsT5Mbw2UbGs_wl1jhp7xPFu7lq9tXQoV2xRim_el9ZOEO2gIYvZChP8A",
			"signature":   "dafe99df9" + "28e5a7f87" + "ac78ad8bf" + "4ba2832d1" + "d009df40f" + "8ee1b3dc7" + "4cc4ba6c7" + "\x38",
		},
	}
	zx4kKrr := []map[string]string{
		{
			"certificate": "MIIC2zCCAcMCAQAwgZUxDjAMBgNVBAoTBUlCIFBGMRcwFQYKCZImiZPyLGQBGRYHU01HNzcwRjFJMEcGA1UECxNAOWFmOTQ4MTUxMDViN2Y1ZTNhM2ZlYjEwNjZkMTE2N2YyNzBhNTg0YjlkZWQwODIyNzM4MDBkZGFhY2RiYTgzZTEfMB0GA1UEAwwWcmVnaWFuZW1tQHRlcnJhLmNvbS5icjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM5-SLerb3ldVhXttDk-hmXog-j_Wli0lfbwCgx_wYKvFTPwo3WzFoKVwHflLnBlljQb-nsPNdkmmDr-reckE3RhASHjoeEBQQupE8jQ64BQgvM5aGHdcpfn8iwJ8dbHXVIkVaByeVwA4Wp0jEb0a6S-c6f3-OPjn-NnA2L1235ArDzJ_4flo-5V1iYuow76UobFFesHeDmALmpufKBjTmPM-2-LdfVZ7vbt6JMgHFxKRJj72hyF4ODqDHpBYThhxE8OWAARyikdvNA4GeKeIoiQA37BF4ihIu3QMGLcNLLZFaq4qZQWfJu9oPXPxzI1mkA-ekYx2ClOHRTl0vaUxOsCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQCNQG-ejyfwSBIiqKVM2BuYUV9nnmnZYT1dLrW29tP70ZYBOnRtUocB8eLOipaDbRERMI22MiW6PkUDMd6Tdri0-BdXdO9eTX7tWXvCNulY3Aog0JkNErjG_RE6XT1LasKHX8Pt0uIOJcWlHVSgr3-wcAp_M9ZYzctylI6arJbxyPd1joNPGMrbSb-SQkiOpSXBfRF5FVsoc5d_x2uB5gFHc_O6X48J3BJrjLb6RHBym806pxzIogvir4jKhAwrhqSYH2-RMF1ARD8LGNDkeWhFbAhVF4fH0GJeIkhhjTrb7jNOb34IfPy-w6u1HhWtUTxGdkoNoK-ao3B2qYLbkBci",
			"signature":   "\x39\x62\x63\x36\x31\x62\x33\x61\x39\x65\x30\x32\x34\x65\x61\x63\x35\x30\x65\x63\x33\x62\x61\x63\x66\x62\x32\x33\x36\x34\x37\x38\x39\x36\x38\x39\x33\x33\x66\x39\x31\x39\x63\x33\x35\x36\x63\x36\x38\x30\x65\x31\x34\x37\x62\x37\x33\x64\x30\x35\x62\x63\x35\x36",
		},
		{
			"certificate": "\x4d\x49\x49\x43\x32\x7a\x43\x43\x41\x63\x4d\x43\x41\x51\x41\x77\x67\x5a\x55\x78\x44\x6a\x41\x4d\x42\x67\x4e\x56\x42\x41\x6f\x54\x42\x55\x6c\x43\x49\x46\x42\x47\x4d\x52\x63\x77\x46\x51\x59\x4b\x43\x5a\x49\x6d\x69\x5a\x50\x79\x4c\x47\x51\x42\x47\x52\x59\x48\x55\x30\x31\x48\x4e\x7a\x63\x77\x52\x6a\x46\x4a\x4d\x45\x63\x47\x41\x31\x55\x45\x43\x78\x4e\x41\x4e\x44\x42\x6c\x4e\x32\x51\x78\x4d\x54\x4a\x69\x59\x6a\x52\x6d\x4d\x7a\x4a\x6c\x4d\x6a\x5a\x6a\x4e\x47\x51\x35\x4e\x7a\x63\x31\x4e\x44\x68\x6d\x4e\x32\x49\x79\x59\x6a\x4d\x79\x4d\x54\x55\x31\x5a\x6a\x6b\x7a\x4d\x44\x56\x6b\x59\x7a\x52\x6b\x4e\x54\x51\x78\x5a\x54\x59\x33\x4d\x47\x51\x33\x4e\x6a\x55\x35\x59\x54\x55\x78\x5a\x47\x59\x32\x4d\x7a\x45\x66\x4d\x42\x30\x47\x41\x31\x55\x45\x41\x77\x77\x57\x63\x6d\x56\x6e\x61\x57\x46\x75\x5a\x57\x31\x74\x51\x48\x52\x6c\x63\x6e\x4a\x68\x4c\x6d\x4e\x76\x62\x53\x35\x69\x63\x6a\x43\x43\x41\x53\x49\x77\x44\x51\x59\x4a\x4b\x6f\x5a\x49\x68\x76\x63\x4e\x41\x51\x45\x42\x42\x51\x41\x44\x67\x67\x45\x50\x41\x44\x43\x43\x41\x51\x6f\x43\x67\x67\x45\x42\x41\x4d\x78\x6d\x70\x66\x50\x37\x47\x74\x52\x53\x32\x58\x61\x6d\x6d\x36\x38\x62\x59\x70\x64\x6a\x2d\x53\x50\x52\x64\x53\x54\x70\x59\x53\x65\x76\x65\x32\x46\x59\x44\x50\x58\x47\x59\x36\x55\x4d\x54\x35\x5f\x55\x42\x57\x66\x71\x57\x50\x49\x6c\x33\x38\x33\x6a\x4c\x56\x30\x46\x4b\x5f\x76\x33\x78\x68\x34\x46\x75\x33\x57\x30\x37\x43\x7a\x63\x59\x4b\x69\x56\x38\x56\x49\x6b\x6b\x69\x31\x55\x55\x4e\x6e\x73\x37\x73\x76\x5f\x49\x75\x4c\x45\x6e\x78\x31\x37\x41\x51\x51\x46\x4f\x45\x4d\x59\x41\x70\x54\x52\x47\x78\x56\x63\x7a\x74\x53\x7a\x65\x58\x63\x36\x4e\x32\x75\x75\x34\x79\x50\x59\x4a\x50\x73\x5a\x53\x56\x38\x2d\x55\x73\x71\x74\x48\x61\x4e\x49\x37\x79\x41\x70\x51\x54\x34\x47\x67\x72\x36\x35\x50\x33\x45\x4b\x74\x32\x76\x44\x65\x42\x6e\x75\x6a\x6b\x6e\x77\x36\x6c\x65\x70\x69\x4e\x6b\x39\x63\x44\x52\x4e\x79\x52\x2d\x71\x6d\x70\x36\x30\x45\x61\x52\x78\x69\x5f\x48\x4d\x30\x4d\x47\x68\x78\x31\x4d\x41\x69\x47\x6a\x56\x65\x58\x5a\x44\x55\x5f\x76\x49\x75\x67\x56\x33\x6e\x69\x6c\x49\x6a\x68\x52\x48\x69\x64\x31\x50\x47\x2d\x35\x48\x4c\x69\x58\x66\x4a\x34\x59\x52\x42\x47\x42\x68\x71\x57\x57\x33\x7a\x70\x32\x54\x66\x4b\x42\x4f\x73\x74\x76\x32\x69\x59\x63\x42\x61\x7a\x5a\x52\x79\x4b\x53\x43\x30\x4c\x50\x41\x5f\x65\x75\x75\x47\x75\x4d\x56\x73\x58\x51\x71\x69\x73\x7a\x79\x61\x76\x72\x71\x63\x77\x61\x6d\x5a\x5f\x59\x48\x6d\x37\x69\x49\x76\x53\x56\x45\x6c\x6c\x73\x79\x32\x58\x38\x43\x41\x77\x45\x41\x41\x61\x41\x41\x4d\x41\x30\x47\x43\x53\x71\x47\x53\x49\x62\x33\x44\x51\x45\x42\x43\x77\x55\x41\x41\x34\x49\x42\x41\x51\x41\x33\x31\x6a\x38\x6c\x43\x6e\x72\x6b\x32\x69\x46\x76\x76\x2d\x45\x76\x75\x61\x47\x49\x69\x79\x35\x34\x7a\x4d\x72\x6a\x78\x4d\x4f\x52\x46\x64\x76\x33\x6d\x6f\x63\x79\x44\x78\x79\x41\x77\x78\x36\x68\x69\x32\x48\x65\x6f\x75\x6a\x37\x54\x62\x4f\x2d\x73\x70\x70\x6c\x5a\x73\x44\x32\x34\x33\x53\x47\x66\x4a\x47\x50\x48\x69\x2d\x61\x4c\x61\x6b\x74\x6c\x73\x71\x58\x70\x63\x42\x49\x4e\x39\x70\x56\x35\x58\x50\x4f\x50\x72\x54\x6f\x65\x59\x2d\x34\x51\x69\x67\x59\x53\x34\x59\x35\x38\x72\x77\x36\x39\x62\x31\x72\x70\x57\x46\x70\x78\x39\x37\x6d\x52\x79\x41\x68\x6f\x4a\x72\x34\x72\x4a\x59\x4f\x4b\x67\x32\x4c\x39\x4c\x6c\x47\x55\x56\x34\x45\x5f\x4f\x2d\x42\x30\x70\x59\x76\x4c\x5a\x4b\x75\x53\x6d\x6a\x52\x79\x36\x54\x53\x55\x66\x76\x59\x32\x78\x5f\x65\x31\x5f\x55\x5a\x57\x48\x52\x6f\x50\x61\x32\x57\x6c\x57\x4b\x78\x42\x73\x4f\x66\x72\x59\x45\x73\x5a\x36\x76\x63\x4a\x51\x39\x66\x74\x69\x4e\x70\x65\x39\x4c\x70\x4c\x65\x61\x6d\x52\x6b\x39\x2d\x65\x76\x41\x68\x4a\x38\x51\x4a\x61\x58\x41\x69\x32\x63\x34\x50\x65\x35\x56\x76\x31\x53\x64\x65\x52\x36\x44\x41\x67\x52\x67\x41\x47\x70\x68\x4f\x67\x77\x30\x68\x72\x79\x6e\x61\x6c\x34\x6d\x39\x55\x38\x39\x50\x2d\x36\x57\x57\x77\x7a\x32\x6e\x43\x63\x39\x71\x5a\x33\x53\x54\x76\x4e\x38\x7a\x67\x73\x6b\x51\x48\x43\x35\x52\x4f\x43\x61\x36\x33\x74\x44\x34\x50\x72\x61\x37\x5f\x67\x51\x7a\x67\x47\x65\x4a\x6d\x6b\x56\x32\x43\x55\x72\x75",
			"signature":   "68e6dae56de3250224028d1818d42f12faa9f08e408f5abf1ec23229dcd6c34e",
		},
		{
			"certificate": "MIIC2zCCAcMCAQAwgZUxDjAMBgNVBAoTBUlCIFBGMRcwFQYKCZImiZPyLGQBGRYHU01HNzcwRjFJMEcGA1UECxNANzdmNmRiOWY2MjQ5ODE0ZmY4NTZiYzIyYmUwNjA2ZDA5YjFhMzVhM2FjZDEzMTA1MjQ4ZWZhY2I2OWE1YmNiNTEfMB0GA1UEAwwWcmVnaWFuZW1tQHRlcnJhLmNvbS5icjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPH4RYOM5D_dEDaEmVRFKFORm8oJ70U3j14j98NlVDCy1FiT4josMJqphP9NfdeadtS9JeG7orPsc7gSE0D1eNV2pHii7Ot8ghb_FjBfWCiUiuKTv7s266QhWJ-LnHXMh9e5ZkfNz9-zehpM5htActdN6KJuid22Ud1sBvhpVgFeccUW7r_-KS2MYvX8KqHyGMaevWQkQGoZeSErFdWNxW-9ppXzrAD_zFc1NdQp8ciVwavkbazV1TZMCjkqwkJS1kGAPWZJhZ6_rem1Uyhy1L0CkXRck_718k-k5xdjV1qTlumsyquvvwH15OzM_2w9T14SChp4L-MGdqA6FnbnlpMCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQDcslP2IQF-F6hrLOTCJXVPNJxiVwwYeXkwO2kst59MMMWQiP5_VftxUgSLWHmPbgorMw_f5-4eC6KV4zy08MAFXjEeFn2DE5IDtrEp7lNVOObMKUi6rzfbi7xuFWESFs6uNmfx25GEmlTtqMFRTAbfwxlnq6HhXpwpdv_HYZP1qyfNpqO4Cd17oHe8amV5bHmUGgi4xdbGYbET2Cdy9xlFDLYEYLp3tcsyinx5d5ooLkUlGHO0rRasf59O4OdX2JQmggaHpQUMta_2v0amWIhCBq4QyMUjpidBTHDCYh-cMM8Cyfjo34yKW_aSFg-JQgKvAsTN0pme2-fXIpMRCCjB",
			"signature":   "6c087375efcb770a0005ab736e9aa409b73451193faff979b2d620320667afdf",
		},
		{
			"certificate": "MIIC2zCCAcMCAQAwgZUxDjAMBgNVBAoTBUlCIFBGMRcwFQYKCZImiZPyLGQBGRYHU01HNzcwRjFJMEcGA1UECxNAODZjMjFjOTBjOGQzYmIxMThjNjZjM2YxNWYzYjVkMGI2MDZjOGY5NWQxNTNmYTI4MjQ1ZDdjYTQ1NmQ4ZGMxNDEfMB0GA1UEAwwWcmVnaWFuZW1tQHRlcnJhLmNvbS5icjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN6pEYAmWBgGEh319piN24YMTk5zyXqR9xGoySg1OBzsrwLIU_7cua_6I1S0S-VgQk260WF-JWtKPR-zZWOc1fx1YCtDYN3YjMeVLAa-_MFX1qP0VcO-kmpJ3VFu4yQnRIub7oQrmYu1e0UqDOwBnTDurgYQckmB2SSmvcpSQtXIlIiQ-RlH50ftDXqRlA5Wh-U_1Q_b1PWYjUTQgb3CQ51o_sNC6TBWiNR8Am1gjgTxUjP6QDnSPA9SiQ-YzZIB46HlHjb3Sy1lTS89POlps6pF0GPhEYGGLZWwyZ0ik89ovQG-UDOtc6rrhBScXUOG3FSaLGDYeWi6oF6ToyEdawcCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQDcE8X6Co4x4KpXqH9R-pxezqYLAsvsu-APhRAS9cUJqYx_s-UuBHlkZ_NCBaIxklKVh_9O-DOY0IXSp1UTE7UK80TOhxrNZOTUU6v0jSWqbs-vA1sJmngU9_Y2c3S_N1hSeqXt8NE27peLaT9lRxX_wJBVUWwZlq5IFcBFcfbz-_Uq6kKKByPTRGA5WUlap1We3F7iQfc-gsDOOS5WEShMlLCB0-zJGIPVyE6B7KJQzAiO4ZcIS5kNsEvrqr9vnkz0VEqxs_gdUDr7sMa518juQEKoaUQkdG9fDwtfojuke5ukXbWMpXHn6va7-CnoJT70nokFToJR8n8j5UShn56Y",
			"signature":   "ed61a1ec979db653838cc8df8f39d560b636790fd2f9d5fc4faa8016361d2e05",
		},
		{
			"certificate": "MIIC2zCCAcMCAQAwgZUxDjAMBgNVBAoTBUlCIFBGMRcwFQYKCZImiZPyLGQBGRYHU01HNzcwRjFJMEcGA1UECxNANzlmZTQyYzQ1YzNmODAyY2FmNmJmODVmOTVhYjJhYTZkYTc5ODQ5OGRlZmE2Njk0YjhjNTc3Nzk5MWYwYzIzNTEfMB0GA1UEAwwWcmVnaWFuZW1tQHRlcnJhLmNvbS5icjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALENPsSHoulZk7oMz3wwFATXVw3-m0BASE1EJFQ-Uw8zd5_QA6xdGXSNruJ9Motv5HO_j2WeUczIfmzlnUzCDKlcPjCsCyO_kEyOFYaZzS4Kf6lhDsZXPjMW8d-d0Q5AIiNz06wKVjwzyMgX97XhK7PAmyzLuKnqjp6792JgRde2duZdMHggniaXoRj0TTowjWCrODN-2_Zy0MpPamjkBds7HZFKKMa5Stz9rlgtNEGglYGkwCCuQWXWtCy-zj7QPZmRiwIMINDLcSo_A3kN9DcssI-MazcbDaLWZe5lUnFX1EiQPf9oazb7orzwLgJAwIhuLmEZZ1XIp8gkPox2TaUCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQBCXxccGydauXSv5WCXq4d1TUfEXx3q_gm2v28cX6IckW9kAshCbRiVvFM7BJ6O_8VLHolqVnxLbmgRHcQxeppsuwL0plmF1-71Fw0AFZqG40dqLzghTQ9w1JjGcxhhkHN1psyUqzt8T2QJqW_Qq94Wj0o8TYNGzRtAcVZ0MfCfI33qxzaBKCiP56zA4i_wbq-P9QUQ-CNVLRvTEMtJNbNb5w7w-Ro8cYVZvOWQect8xSvj6vBRZa_9Sl31_j-92Td032fP1tJUzsZ5pvjsb0eikp30HiITEAkczrKet05a5ix3prtqxyCRpNlDRQ3JPGhcdpC4qftyhNfKo_V6goLw",
			"signature":   "9285896e327e0da93a077371b79659616fa36667ed1b420501d733b05c370c32",
		},
		{
			"certificate": "MIIC2zCCAcMCAQAwgZUxDjAMBgNVBAoTBUlCIFBGMRcwFQYKCZImiZPyLGQBGRYHU01HNzcwRjFJMEcGA1UECxNAZWJkNWQ1MzFjMTM1Zjc4ZTRjNzI2NmM0OTc3NTVhOTU2OTA0YTA0MWEwZDJkNmUzZGJkODJkZjc3OGNjNzcxMDEfMB0GA1UEAwwWcmVnaWFuZW1tQHRlcnJhLmNvbS5icjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAO8pRRqaZOHJrGqfJ6B0X6yULquPKeCPUlgsa-S6YX9LjlM2IVPGXUoGV4YsLwRMV6K9Qxh_OSQnbQ2P-x3aaHxYK6K4NcxPeknTWdNzr2phWStFVEdgNBLdhbiMCkHpSgpqVVrp16N3q30UjJb00niNM32MSDTfF1r41loedqvU-GGE3L_E6VrmaN62ejQ-68Y64DQxBjrtjQljd4K3Ef0jbDppb5BjzzR6it3jjpuLhmDRYSC9zBhSNefbTcjSdV1ijbL0Ou2gTPEH93J_EpIUQ-VdNqizLIn6rSeqyXnR5nfEzpdZE8HuD8_pbwWw4Pmls_cNAx01UEZmLCfr5u0CAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQCYjugPSlbILTG_ln6KD9TWBGUMEAy0pbVMkWLC8tCJV50tqpStF5FbbsWAuKKw6Ct3_6OizSt8PSmfdUB3jSVwm13xgniVuLuXNt-N1MdqIog506szVlmkzDueqBeYkKCXe0OhsD3jYCYGxCdrH9OLanOeWjBtOramwWFx3-sVmvmYTazUptJ3r8K8Sfi030GCAOCwF-XhsTwzfKWSYLQXQzRB-mtNjQonHZbe0tK4EfYujiPtEMEaryR5gPy6sUyJw7vIK0088Qn6Tv04F2y1GmcE4HsoJ78wNUshvkLSPgo010ZZgRo2EBZGBNQQVAxzRaEfIu-wTxlIeZyp5XDC",
			"signature":   "ca856ca67f1ef4f8e4d9344a3e32f706e9ac57e0f78878f4e362078dc4964534",
		},
		{
			"certificate": "MIIC2zCCAcMCAQAwgZUxDjAMBgNVBAoTBUlCIFBGMRcwFQYKCZImiZPyLGQBGRYHU01HNzcwRjFJMEcGA1UECxNANjZkZTA2OWY5YzRjMzM1NDFkOGIwYmY4YWU3N2Y1NjQ0MGI0MDk1YzEzOWZmYmI4YjEwOTUwNmFhMDBmZTM5YzEfMB0GA1UEAwwWcmVnaWFuZW1tQHRlcnJhLmNvbS5icjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM28gM8BAWOW--oZiIgZragFWzdb9duDUuLCkn-5M_q5GbmQS9czP1JjJYOkXaZz322SGVT9_XSvMJbvuwdn2A9bxqpRrYamyyEkgQZiQvFPK7g13vs9hOQrIqvaPYbPxsbsfSy7JCD-InK67F2erwqe4ULlDvAS2-wHt0szvg53_bqrAXxlIqciptm3JJJP66iw6ClB4illi-XVJFxiuvvizYXU_o4TUiSsrWwsmvHaxhnBMgsi_WyG6H4u5v2D36U5qtFPIOTtsI3wDgo1cHafNTjJ1420criSF0LvMxurZh4S77PWlxReSrEt9HzpvI_wq3kt8-g5FsZELQgJel8CAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQC4WYmG8lRwNzgYp9uSbA4xnz1yVJCR9cruYMDEJQ1FKBBOBc-vrwOtlGbQHiuTUmBuPBa2aysI2k96E-60S_XVPXiaYpeU-TRslrxf72-cre7wMxwHAhdRF8gX7b0SA8pIDpdTF5oIYhey7CpOaCJ_fn6S_qpwkIr9HzcIglBfE6q7Br2dSCSDSczv_X8xh3TSqZWChT7Lgk-RP2DykYstz9mA5NGGWVx2CUfQa6JoLfCwlIOlQNrjVQVxOnRlXHkjGIC9JoBqTzfSiRPohcejBPPehgsuApMhJlDl8Ka6ian3mddGWkZ0l7QXi2kNfcBbJNWMp1g56HISelWnirox",
			"signature":   "3aacfacd85080c9ebaec44d5d8a9f027d93c028b932959a9a3b04b1fcc712563",
		},
		{
			"certificate": "MIIC2zCCAcMCAQAwgZUxDjAMBgNVBAoTBUlCIFBGMRcwFQYKCZImiZPyLGQBGRYHU01HNzcwRjFJMEcGA1UECxNAMDFiZTk3OTA3OWQwMzQxZTZkMmU3NDBlYTBiODFlNTc1ZmFjNzFlYzEyMTYzY2JmYzQ5MzY5ZmI3NWE0YTdiMjEfMB0GA1UEAwwWcmVnaWFuZW1tQHRlcnJhLmNvbS5icjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKyB4GdYv-3uEmQpf1XqYdyG_wu5686Bc54BoVgPJJJdUA1StXMhmgwf_p8lnd18LSfFYZlLU8NgRtWrSzc83LpljULid5O_xblDuXrCs5PcQ2Ojpf7m1FOdFRsqX3abFMGdegop1HxzCsotMFalgIcnGvkh8co3wYYX54GybniZIBe9haz1TS7cF4dqaskmGMlkbeIv6TCHdAyjGgFPwu4T7d1C63zYo1I0BTZ1Sib-Vo1wD_LBmg7990Uw8qx4B_mBbTTWAkbqDvczqIc6_Jq7JLnEppw2PsdzmVN-4LIP4mGkdAgAj_e_T6v-AZ8jKRdUgm2FBtKAEeJz4KqVRZUCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQComvi4MHYXQJHgGvd0x4ufINJuSrs_loDUpt9lmgP6OnRSpF0qK7CdtWBJWDyHMceOimw5ZdQBls3kahXag-P_u0qZwJkQb_RIlVXZiUyONsY_-9cxMZupXcbmV_AG1zShW1AhvIlBNnesS-3Zde1YsvpQUbxg6d5sp0YnlU22QwAXaBQ5IgTZgDjvyAs_HtejLrN6ZNTUEd92nCEDAUGQn8BHVuz4xY0kO8mxMry5Tmrm2zwbfxlXxfCfvXvJHDe5zWXI-76wXpyOHqMqCSacik5K_qR-AFAVcDrrTtrrjLqNSmw-LZhfIEdJ22yiqj9Z7Oko4fL-l21f4Q_cjUxy",
			"signature":   "b55da96ab836bdcc2c6e1d29712e24d52fd9514219def6832a920f51d00a174b",
		},
		{
			"certificate": "MIIC2zCCAcMCAQAwgZUxDjAMBgNVBAoTBUlCIFBGMRcwFQYKCZImiZPyLGQBGRYHU01HNzcwRjFJMEcGA1UECxNAMTRhOTFhOTZjOGQwNzRkNWI4NWM1NGIwZjQ3NGYyM2QwYWE2Y2JhNzcyMjMzODUxNDkyNGJlZmIwYTEwYTE1ZDEfMB0GA1UEAwwWcmVnaWFuZW1tQHRlcnJhLmNvbS5icjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALdOjdNT0H8VvnKl2jXMkKx9iV-Q7XWQEmLbl7wmJEOd6qLGSChDkFIB5h6QmVAcoMscf_RJvVwZK-PNOHXo9P3qmreF-Wf4xptVSmiHONjFbuqX82zY31zw58b3C2P7CIV5u_tiqpuOsV_SfD4FruyfU_uVyghs3iuEEbXNsZMM3dHbmp9WbJVWySHByKbSsT-eU0KZ5XIQHhqbNkDo4kadocdHH34HG7jE8ZJVrd5ZfOsksiO-ljWePAdgjpyl-oGLGPCAIMB8AKs0OW_0hy220wGg_RNsFeoul9EQWvQjnK7l0tXZRQ4_IaNftqQ0ihboPNEL-uVS_pF7Gwbs0XMCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQCzfQ0Sfu3co1Tn1FiO6emcW4gAXNT3MAX685AJ2EuIFYsBSKz7ftdEhMEF1J6lfnP2DHQt02TAjwrNRn_IsJRDmtRzRfGUvbmuzfm4AjJXP0dYMudNYgfJud0GBW6SO3qpKIoXDOZOBRvtpp-cEI0JIJVJxkq2iYrBlx2XPaoTQnTcgZDMWz77q1ZHRszlfPw6neKgQ9ZCl-5tEPJTn2DcQkFIvvg8cXjj7hogp6ZYE15-__LApFCePl8jC5wyDhYvb-xiPfKgDgqD4cDFGDoXPVV0XZNG8nXfoXgAIU4CBLv49_pX4qM4AAa3nZGhoWXEwLvG6Pyd6LVa97zTb_PW",
			"signature":   "2cb6f6f21f79426a7a3abe4dc8a5421ac05a46085a6abcf25b2ef19165fa856c",
		},
	}
	ZhYazAU := append(zx4kKrr, DaIJE0...)
	// Substituir MathRand.Seed por um gerador local
	r := MathRand.New(MathRand.NewSource(time.Now().UnixNano()))
	return ZhYazAU[r.Intn(len(ZhYazAU))]
}

// Captcha && Bypass

func SolveMobileCaptchaResponse(KEY, appPackageName, appKey, appAction string) (string, error) {

	client := &http.Client{}
	req, err := http.NewRequest("POST", "https://api.nextcaptcha.com/createTask", strings.NewReader("{\"clientKey\":\""+KEY+"\",\"task\": {\"type\":\"RecaptchaMobileTaskProxyless\",\"appPackageName\":\""+appPackageName+"\",\"appKey\":\""+appKey+"\",\"appAction\":\""+appAction+"\"}}")) // Updated appAction
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// log.Println(string(body))

	var taskResponse map[string]interface{}
	if err := json.Unmarshal(body, &taskResponse); err != nil {
		return "", err
	}

	taskID, ok := taskResponse["taskId"].(float64)
	if !ok {
		return "", fmt.Errorf("task ID not found in the response")
	}

	for {
		time.Sleep(time.Second)

		payload := map[string]interface{}{
			"clientKey": KEY,
			"taskId":    taskID,
		}

		jsonPayload, err := json.Marshal(payload)
		if err != nil {
			return "", err
		}

		req, err := http.NewRequest("POST", "https://api.nextcaptcha.com/getTaskResult", bytes.NewBuffer(jsonPayload))
		if err != nil {
			return "", err
		}

		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}

		// fmt.Printf("[GERANDO CAPTCHA] -> %s\n", string(body))

		var response map[string]interface{}
		if err := json.Unmarshal(body, &response); err != nil {
			return "", err
		}

		status, ok := response["status"].(string)
		if !ok {
			return "", fmt.Errorf("status not found in the response")
		}

		if status == "ready" {
			captchaResponse, ok := response["solution"].(map[string]interface{})["gRecaptchaResponse"].(string)
			if !ok {
				return "", fmt.Errorf("captcha response not found in the response")
			}

			if captchaResponse == "ERROR_CAPTCHA_UNSOLVABLE" {
				return "", fmt.Errorf("ERROR_CAPTCHA_UNSOLVABLE")
			}

			return captchaResponse, nil
		}
	}
}

func SolveReCaptchaV3HS(KEY, websiteURL, websiteKey, pageAction string) (string, error) {

	client := &http.Client{}
	req, err := http.NewRequest("POST", "https://api.nextcaptcha.com/createTask", strings.NewReader("{\"clientKey\":\""+KEY+"\",\"task\": {\"type\": \"ReCaptchaV3HSTaskProxyLess\",\"websiteURL\": \""+websiteURL+"\",\"websiteKey\": \""+websiteKey+"\",\"pageAction\": \""+pageAction+"\"}}"))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// log.Println(string(body))

	var taskResponse map[string]interface{}
	if err := json.Unmarshal(body, &taskResponse); err != nil {
		return "", err
	}

	taskID, ok := taskResponse["taskId"].(float64)
	if !ok {
		return "", fmt.Errorf("task ID not found in the response")
	}

	for {
		time.Sleep(time.Second)

		payload := map[string]interface{}{
			"clientKey": KEY,
			"taskId":    taskID,
		}

		jsonPayload, err := json.Marshal(payload)
		if err != nil {
			return "", err
		}

		req, err := http.NewRequest("POST", "https://api.nextcaptcha.com/getTaskResult", bytes.NewBuffer(jsonPayload))
		if err != nil {
			return "", err
		}

		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}

		// fmt.Printf("[GERANDO CAPTCHA] -> %s\n", string(body))

		var response map[string]interface{}
		if err := json.Unmarshal(body, &response); err != nil {
			return "", err
		}

		status, ok := response["status"].(string)
		if !ok {
			return "", fmt.Errorf("status not found in the response")
		}

		if status == "ready" {
			captchaResponse, ok := response["solution"].(map[string]interface{})["gRecaptchaResponse"].(string)
			if !ok {
				return "", fmt.Errorf("captcha response not found in the response")
			}

			if captchaResponse == "ERROR_CAPTCHA_UNSOLVABLE" {
				return "", fmt.Errorf("ERROR_CAPTCHA_UNSOLVABLE")
			}

			return captchaResponse, nil
		}
	}
}

func SolveImageCaptcha(host, Key, imageBase64 string) (string, error) {

	transport := http.Transport{}
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //set ssl

	client := &http.Client{
		Timeout: time.Duration(15) * time.Second,
	}
	client.Transport = &transport

	form := url.Values{}
	form.Set("body", imageBase64)
	form.Add("method", "base64")
	form.Add("key", Key)
	form.Add("json", "1")

	req, err := http.NewRequest("POST", "https://"+host+"/in.php", bytes.NewBuffer([]byte(form.Encode())))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var resp *http.Response
	err = retry.Do(
		func() error {
			var err error
			resp, err = client.Do(req)
			return err
		},
		retry.Attempts(3),
		retry.OnRetry(func(n uint, err error) {
			fmt.Println(err.Error())
		}),
	)

	if err != nil {
		return SolveImageCaptcha(host, Key, imageBase64)
	}
	defer resp.Body.Close()

	// Capturando o retorno da request em Bytes e transformando em String
	bodyByte, _ := io.ReadAll(resp.Body)

	bodyText := string(bodyByte)

	id := gjson.Get(bodyText, "request").Raw

	color.Green("ID: %s -> BODY: %s", id, bodyText)

	i := 0
	for {
		req, _ := http.NewRequest("GET", "https://"+host+"/res.php?key="+Key+"&action=get&id="+id, nil)

		err = retry.Do(
			func() error {
				var err error
				resp, err = client.Do(req)
				return err
			},
			retry.Attempts(3),
			retry.OnRetry(func(n uint, err error) {
				fmt.Println(err.Error())
			}),
		)

		if err != nil {
			if i > 5 {
				return "", err
			}
			i++
			continue
		}
		defer resp.Body.Close()

		// Capturando o retorno da request em Bytes e transformando em String
		bodyByte, _ := io.ReadAll(resp.Body)

		bodyText := string(bodyByte)

		if bodyText == "CAPCHA_NOT_READY" {
			time.Sleep(1 * time.Second)
			continue
		}

		if bodyText == "ERROR_WRONG_CAPTCHA_ID" {
			return "", fmt.Errorf("ERROR_WRONG_CAPTCHA_ID")
		}
		return bodyText, nil
	}
}

func SolveCaptcha(host, Key, site, siteKey string) (string, error) {

	transport := http.Transport{}
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //set ssl

	client := &http.Client{
		Timeout: time.Duration(15) * time.Second,
	}
	client.Transport = &transport

	form := url.Values{}
	form.Set("googlekey", siteKey)
	form.Set("pageurl", site)
	form.Add("method", "userrecaptcha")
	form.Add("key", Key)
	form.Add("json", "1")

	req, err := http.NewRequest("POST", "https://"+host+"/in.php", bytes.NewBuffer([]byte(form.Encode())))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var resp *http.Response
	err = retry.Do(
		func() error {
			var err error
			resp, err = client.Do(req)
			return err
		},
		retry.Attempts(3),
		retry.OnRetry(func(n uint, err error) {
			fmt.Println(err.Error())
		}),
	)

	if err != nil {
		return SolveCaptcha(host, Key, site, siteKey)
	}
	defer resp.Body.Close()

	// Capturando o retorno da request em Bytes e transformando em String
	bodyByte, _ := io.ReadAll(resp.Body)

	bodyText := string(bodyByte)

	id := gjson.Get(bodyText, "request").Raw

	color.Green("ID: %s -> BODY: %s", id, bodyText)

	i := 0
	for {
		req, _ := http.NewRequest("GET", "https://"+host+"/res.php?key="+Key+"&action=get&id="+id, nil)

		err = retry.Do(
			func() error {
				var err error
				resp, err = client.Do(req)
				return err
			},
			retry.Attempts(3),
			retry.OnRetry(func(n uint, err error) {
				fmt.Println(err.Error())
			}),
		)

		if err != nil {
			if i > 5 {
				return "", err
			}
			i++
			continue
		}
		defer resp.Body.Close()

		// Capturando o retorno da request em Bytes e transformando em String
		bodyByte, _ := io.ReadAll(resp.Body)

		bodyText := string(bodyByte)

		if bodyText == "CAPCHA_NOT_READY" {
			time.Sleep(500 * time.Millisecond)
			continue
		}

		if bodyText == "ERROR_WRONG_CAPTCHA_ID" {
			return "", fmt.Errorf("ERROR_WRONG_CAPTCHA_ID")
		}
		return bodyText, nil
	}
}

func SolveCaptchaWithDomain(host, Key, site, siteKey, domain string) (string, error) {

	transport := http.Transport{}
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //set ssl

	client := &http.Client{
		Timeout: time.Duration(15) * time.Second,
	}
	client.Transport = &transport

	form := url.Values{}
	form.Set("googlekey", siteKey)
	form.Set("pageurl", site)
	form.Set("domain", domain)
	form.Add("method", "userrecaptcha")
	form.Add("key", Key)
	form.Add("json", "1")

	req, err := http.NewRequest("POST", "https://"+host+"/in.php", bytes.NewBuffer([]byte(form.Encode())))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var resp *http.Response
	err = retry.Do(
		func() error {
			var err error
			resp, err = client.Do(req)
			return err
		},
		retry.Attempts(3),
		retry.OnRetry(func(n uint, err error) {
			fmt.Println(err.Error())
		}),
	)

	if err != nil {
		return SolveCaptcha(host, Key, site, siteKey)
	}
	defer resp.Body.Close()

	// Capturando o retorno da request em Bytes e transformando em String
	bodyByte, _ := io.ReadAll(resp.Body)

	bodyText := string(bodyByte)

	id := gjson.Get(bodyText, "request").Raw

	color.Green("ID: %s -> BODY: %s", id, bodyText)

	i := 0
	for {
		req, _ := http.NewRequest("GET", "https://"+host+"/res.php?key="+Key+"&action=get&id="+id, nil)

		err = retry.Do(
			func() error {
				var err error
				resp, err = client.Do(req)
				return err
			},
			retry.Attempts(3),
			retry.OnRetry(func(n uint, err error) {
				fmt.Println(err.Error())
			}),
		)

		if err != nil {
			if i > 5 {
				return "", err
			}
			i++
			continue
		}
		defer resp.Body.Close()

		// Capturando o retorno da request em Bytes e transformando em String
		bodyByte, _ := io.ReadAll(resp.Body)

		bodyText := string(bodyByte)

		if bodyText == "CAPCHA_NOT_READY" {
			time.Sleep(200 * time.Millisecond)
			continue
		}

		if bodyText == "ERROR_WRONG_CAPTCHA_ID" {
			return "", fmt.Errorf("ERROR_WRONG_CAPTCHA_ID")
		}
		return bodyText, nil
	}
}

func Getbmp(post string) ResponseData {
	url := "http://185.190.140.39:1337/akamai/bmp"

	payload := strings.NewReader(post)

	req, _ := http.NewRequest("POST", url, payload)

	req.Header.Add("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return ResponseData{}
	}

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return ResponseData{}
	}

	var responseData ResponseData
	err = json.Unmarshal(body, &responseData)
	if err != nil {
		return ResponseData{}
	}

	return responseData
}

// Models

type ResponseData struct {
	Sensor         string `json:"sensor"`
	AndroidVersion string `json:"androidVersion"`
	Model          string `json:"model"`
	Brand          string `json:"brand"`
	ScreenSize     string `json:"screenSize"`
}
