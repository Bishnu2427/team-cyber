FROM nginx:alpine

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

# Our config
COPY docker/nginx.conf /etc/nginx/conf.d/teamcyber.conf

# Static files served directly by Nginx
COPY frontend/static /app/frontend/static

EXPOSE 80
