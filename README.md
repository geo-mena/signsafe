<div align="center">
  <p>
    <h2>
      SignSafe - Digital Signature Validator
    </h2>
  </p>

![Docker Badge](https://shields.io/badge/Docker-20.10.7-blue?logo=docker)
![Java Badge](https://shields.io/badge/Java-11-red?logo=java)
![Spring Boot Badge](https://shields.io/badge/Spring%20Boot-2.7.0-green?logo=spring)
![PDFBox Badge](https://shields.io/badge/PDFBox-2.0.24-blue)
![Maven Badge](https://shields.io/badge/Maven-3.8.4-blue)

</div>

This project implements a REST service in Spring Boot to validate digital signatures in PDF documents. It is capable of processing signatures from different Ecuadorian certification entities such as Security Data, UANATACA, among others.

## 🎉 Features

- Validation of digital signatures in PDF documents
- Extraction of signer information:
  - Full name
  - ID number
  - Certification entity
  - Date of signature
  - Certificate validity status
- Support for multiple signatures in a single document
- Support for different Ecuadorian certification entities

## 🛠️ Stack

- **[Java](https://www.java.com/)** - Programming language
- **[Spring Boot](https://spring.io/projects/spring-boot)** - Framework for creating web applications
- **[PDFBox](https://pdfbox.apache.org/)** - Library for working with PDF documents
- **[Bouncy Castle](https://www.bouncycastle.org/)** - Cryptography library
- **[Maven](https://maven.apache.org/)** - Dependency management
- **[Docker](https://www.docker.com/)** - Containerization platform

## 🚀 Installation

1. Clone the repository:

```bash
git clone https://github.com/geo-mena/signsafe.git
cd signsafe
```

2. Build the project:

```bash
mvn clean package
```

3. Run the application using Docker:

```bash
docker compose up -d
```

Or run the application directly:

```bash
java -jar target/validador-firmas-0.0.1-SNAPSHOT.jar
```

## ⚡️ Usage

The REST service exposes a single endpoint to validate digital signatures in PDF documents:

```plaintext
POST /api/validador/verificar
Content-Type: multipart/form-data
```

The PDF file must be sent as a multipart form with the name `file`. The service will respond with a JSON containing the information of the digital signatures found in the document.

## 📄 Example

```json
{
  "success": true,
  "message": "Se encontraron 1 firma(s) en el documento",
  "data": [
    {
      "nombreCompleto": "JUAN PEREZ",
      "cedula": "1234567890",
      "entidadCertificadora": "SECURITY DATA S.A. 2",
      "fechaFirma": "2024-11-26T02:02:44.000+00:00",
      "esValida": true
    }
  ]
}
```

## 🔒️ Validation Features

The service performs the following validations:

- Extraction of digital certificate data
- Verification of certificate validity
- Support for different digital signature formats
- Handling of multiple signatures in a document

## 🚨 Known Limitations

- Does not perform OCSP verification
- Does not verify revocation lists (CRL)
- Certificate chain validation is not implemented

## 🤝 Contributing

If you want to contribute to the project:

1. Fork the repository
2. Create a branch with your feature: `git checkout -b feature/new-feature`
3. Commit your changes: `git commit -am 'Add new feature`
4. Push to the branch: `git push origin feature/new-feature`
5. Submit a pull request

## 🔑 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

The MIT license is a permissive software license that allows:

- Commercial use
- Modification
- Distribution
- Private use
