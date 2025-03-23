# FileGuard

## Abstract

Final project of [Information And Organisational Security](https://www.ua.pt/en/uc/4143) of [Universidade de Aveiro](https://www.ua.pt/) <br>
A criptographically secure repository for documents for organizations that can be securely shared among several people.

## Key Points

- Implemented a TLS-like secure channel in the application layer (http), using ECC, so all the communications are encrypted, even if not using https.
- File encryption assured with AES symmetric encryption
- File integrity assured with digests (sha256).
- Implemented a Role-Based Access Control (RBAC) for accessing the documents.

## Notes

- **Project Specification:** [Specification](./specification.md)
- **Server Code** [Server](./delivery3/repository)
- **Client Code** [Client](./delivery3/commands)
- **Project Report and ASVS Chapter 6 L3 Analysis:** [Report](./delivery3/Report.pdf)

## Tools

- [Flask](https://flask.palletsprojects.com/en/stable/)
- [Cryptography](https://cryptography.io/)
- [PostgreSQL](https://www.postgresql.org/)
- [SQLAlchemy](https://www.sqlalchemy.org/)

## Grade

20.0 / 20.0
