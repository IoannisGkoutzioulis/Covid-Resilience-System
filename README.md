
# Covid Resilience System (PRS_System)

A secure PHP-MySQL web application designed to support pandemic resilience. This system manages vaccination records, government official access, merchant activity, critical item monitoring, and user identity during pandemic events.

---

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Database Schema](#database-schema)
- [Dependencies](#dependencies)
- [Troubleshooting](#troubleshooting)
- [Contributors](#contributors)
- [License](#license)

---

## Introduction

This Pandemic Resilience System (PRS_System) provides centralized functionality to manage citizens, doctors, merchants, vaccination data, and documents in a structured and secure environment. It supports decision-making by providing dashboards, logs, and automated approvals for critical functions.

---

## Features

- 🔐 Role-based user access (Admin, Citizen, Doctor, Merchant, Official)
- 📊 Admin dashboard with key metrics (users, vaccinations, officials, etc.)
- 💉 Vaccination and doctor record management
- 📦 Merchant and purchase tracking
- 🗂️ Secure document upload system
- 📁 File and log management
- 🧾 Access control and logging
- 📄 SQL-backed database for secure, persistent storage

---

## Installation

### Prerequisites

- PHP 7.4+
- MySQL or MariaDB
- Apache or Nginx web server

### Setup Steps

1. **Clone or Extract the Repository**
   ```bash
   git clone <repo_url>
   ```

2. **Configure Web Server**
   - Serve files from the project root
   - Ensure PHP and MySQL extensions are enabled

3. **Set Up Database**
   - Create a new database and import the schema:
     ```bash
     mysql -u root -p < database.sql
     ```

4. **Configure Credentials**
   - Update `config.php` with your DB credentials and settings

---

## Usage

- Access the system via `dashboard.php` in your browser
- Use roles to explore:
  - Admin: manage the full system
  - Doctor: update vaccination entries
  - Official: approve/monitor citizens
  - Merchant: manage resource purchases

---

## Configuration

- **`config.php`** – Set database credentials and environment settings
- **`access_control.php`** – Role-based access logic
- **`uploads/`** – File upload destination
- **`logs/`** – System-generated access and activity logs

---

## Database Schema

Key tables created by `database.sql`:

- `users`: identity and login
- `doctors`: health personnel data
- `vaccination_records`: logs of vaccinations
- `merchants`: suppliers
- `purchases`: merchant supply records
- Additional tables may include access logs, documents, etc.

---

## Dependencies

This is a pure PHP project using built-in libraries such as:

- `PDO` for MySQL connectivity
- `session_*` functions for auth
- File I/O and form handling

No Composer or external packages required.

---

## Troubleshooting

| Issue                         | Solution                                                              |
|-------------------------------|-----------------------------------------------------------------------|
| Blank page or error on load   | Enable `display_errors` in `php.ini` and check `logs/`                |
| Database connection fails     | Confirm `config.php` credentials and MySQL service                    |
| Uploads not working           | Ensure write permissions for `uploads/` directory                     |
| Dashboard shows no data       | Import `database.sql` and add sample data if necessary                |

---

## Contributors

- Developed by academic software developers
- Designed for public health resilience research and simulation

---

## License

This project is open-source and intended for educational and governmental planning use only.
