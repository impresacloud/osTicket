FROM php:8.2-apache

# Install system dependencies for PHP extensions
RUN apt-get update && apt-get install -y \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    libwebp-dev \
    libxpm-dev \
    libzip-dev \
    libxml2-dev \
    libicu-dev \
    libonig-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Configure and install PHP extensions
RUN docker-php-ext-configure gd --with-freetype --with-jpeg --with-webp \
    && docker-php-ext-install \
    mysqli \
    gd \
    mbstring \
    intl \
    zip \
    xml \
    exif

# Enable Apache modules
RUN a2enmod rewrite

# Set working directory
WORKDIR /var/www/html

# Use production configuration for PHP
RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"

# Optional: Adjust php.ini settings for file uploads
RUN echo "upload_max_filesize = 50M" >> $PHP_INI_DIR/php.ini \
    && echo "post_max_size = 50M" >> $PHP_INI_DIR/php.ini \
    && echo "memory_limit = 256M" >> $PHP_INI_DIR/php.ini

# Do not run as root (optional security)
# RUN usermod -u 1000 www-data || true (Apache runs as www-data by default)
