# Local Development Setup with Docker

This guide sets up osTicket for local development using Docker Compose.

## Prerequisites

- Docker (version 20.10+ recommended)
- Docker Compose (version 2.0+)
- Git (for cloning the repo if needed)
- At least 2GB RAM allocated to Docker

## Quick Start

1. **Clone the repository** (if not already):
   ```bash
   git clone https://github.com/impresacloud/osTicket.git
   cd osTicket
   ```

2. **Start the containers**:
   ```bash
   docker-compose up --build
   ```

3. **Access the application**:
   - osTicket installer: http://localhost:8082
   - Database UI (optional): http://localhost:8081 (phpMyAdmin)
   - Mail catcher: http://localhost:8025 (Mailhog)

## Services

- **Web (Apache + PHP 8.2)**: Handles osTicket requests
  - Volume mounted: Your repo directory
  - Port: 8082
  - PHP extensions: mysqli, gd, mbstring, intl, zip, xml, exif

- **Database (MariaDB 10.6)**:
  - User: osticket
  - Password: osticketpass
  - Database: osticket
  - Port: 3306 (internal)

- **Mailhog**: Captures outgoing emails for testing
  - Port: 8025 (web UI), 1025 (SMTP)

## Installation

1. Visit http://localhost:8082 in your browser.
2. Follow the osTicket installer.
3. Use these database details:
   - Host: db
   - Database: osticket
   - User: osticket
   - Password: osticketpass

## Development Workflow

- **Live Reload**: Code changes are immediate since the repo is volume-mounted.
- **Database Persistence**: Data survives container restarts via `db_data` volume.
- **Logs**: View with `docker-compose logs -f`.
- **Shell Access**: `docker-compose exec web /bin/bash` for PHP container shell.

## Cron Jobs

osTicket requires scheduled tasks for maintenance. Set up manually:

1. Add to your system's crontab:
   ```bash
   * * * * * curl -s http://localhost:8082/api/cron.php
   ```

2. Or create a cron container if needed.

## Testing Recommendations

1. **Functional Testing**:
   - Create tickets, assign agents
   - Test email sending via Mailhog UI
   - Verify cron tasks run

2. **Code Changes**:
   - Edit files in your IDE
   - Refresh browser to see changes
   - Check PHP logs: `docker-compose logs web`

3. **Database Inspection**:
   - Use phpMyAdmin at http://localhost:8081
   - Or connect directly: `mysql -h 127.0.0.1 -P 3306 -u osticket -posticketpass osticket`

4. **Performance**:
   - Enable Xdebug for debugging:
     - Add to Dockerfile: `pecl install xdebug` and configure
     - Adjust memory/timeout in php.ini

## Common Issues

- **Permission Errors**: If files created in container need host access, adjust mounts or use `docker-compose exec`.
- **Port Conflicts**: Change ports in docker-compose.yml if 8080/8025/3306 are busy.
- **Build Fails**: Ensure Docker has sufficient resources; rebuild without cache: `docker-compose build --no-cache`.
- **Database Connection**: Wait for DB to initialize; restart web service if needed.
- **Email Not Sending**: Check Mailhog logs; ensure SMTP settings in osTicket point to `mailhog:1025`.

## Stopping and Cleanup

- Stop: `docker-compose down`
- Stop and remove volumes: `docker-compose down -v`
- Remove images: `docker-compose down --rmi local`

## Versions

- PHP: 8.2
- MariaDB: 10.6
- Debian: Trixie (Docker base image)

## Notes

- This setup is for development/testing only; not production-ready.
- Back up your work before major container updates.
- Consult osTicket documentation for advanced configuration.
