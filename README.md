# signsafe - Validador de Firmas Digitales en Documentos PDF

Este proyecto implementa un servicio REST en Spring Boot para validar firmas digitales en documentos PDF. Es capaz de procesar firmas de diferentes entidades certificadoras ecuatorianas como Security Data, UANATACA, entre otras.

## Características

- Validación de firmas digitales en documentos PDF
- Extracción de información del firmante:
  - Nombre completo
  - Número de cédula
  - Entidad certificadora
  - Fecha de firma
  - Estado de validez del certificado
- Soporte para múltiples firmas en un mismo documento
- Soporte para diferentes entidades certificadoras ecuatorianas

## Tecnologías Utilizadas

- Java 11
- Spring Boot 2.7.0
- PDFBox
- Bouncy Castle
- Docker
- Maven

## Requisitos Previos

- Java 11 o superior
- Maven
- Docker y Docker Compose (opcional)

## Estructura del Proyecto

```plaintext
validador-firmas/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/
│   │   │       └── example/
│   │   │           └── validadorfirmas/
│   │   │               ├── config/
│   │   │               ├── controller/
│   │   │               ├── dto/
│   │   │               └── service/
│   │   └── resources/
│   └── test/
├── docker-compose.yml
├── Dockerfile
├── pom.xml
└── README.md
```

## Instalación

1. Clonar el repositorio:

```bash
git clone https://github.com/geo-mena/signsafe.git
cd signsafe
```

2. Compilar el proyecto:

```bash
mvn clean package
```

3. Ejecutar con Docker:

```bash
docker compose up -d
```

O ejecutar localmente:

```bash
java -jar target/validador-firmas-0.0.1-SNAPSHOT.jar
```

## Uso

El servicio REST expone un único endpoint para validar firmas digitales en documentos PDF:

```plaintext
POST /api/validador/verificar
Content-Type: multipart/form-data
```

El archivo PDF debe ser enviado como un formulario multipart con el nombre `file`. El servicio responderá con un JSON que contiene la información de las firmas digitales encontradas en el documento.

### Ejemplo de Solicitud

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

## Características de la Validación
El servicio realiza las siguientes validaciones:

- Extracción de datos del certificado digital
- Verificación de la vigencia del certificado
- Soporte para diferentes formatos de firma digital
- Manejo de múltiples firmas en un documento

## Limitaciones Conocidas

- No realiza verificación OCSP
- No verifica listas de revocación (CRL)
- La validación de la cadena de certificados no está implementada

## Contribución
Si deseas contribuir al proyecto:

1. Realiza un fork del repositorio
2. Crea una rama con tu funcionalidad: `git checkout -b feature/nueva-funcionalidad`
3. Realiza un commit de tus cambios: `git commit -am 'Agrega nueva funcionalidad'`
4. Realiza un push a la rama: `git push origin feature/nueva-funcionalidad`
5. Crea un pull request

## Licencia

Este proyecto está bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

La licencia MIT es una licencia de software permisiva que permite:
- Uso comercial
- Modificación
- Distribución
- Uso privado