# Belial's Cybersecurity Blog

A dark-themed, elegant cybersecurity blog platform built with Express.js and SQLite.

## Features

- 🌑 Dark theme with elegant, clean design
- 📝 Markdown support with syntax highlighting (Dracula theme)
- 🏷️ Tag system for organizing posts
- 📱 Responsive design, mobile-friendly  
- 🔍 SEO optimized with meta tags
- 📡 RSS feed support
- 🛡️ API key authentication for write operations
- ⚡ PM2 ready for production deployment

## Setup

### Prerequisites

- Node.js and npm installed
- PM2 installed globally (`npm install -g pm2`)

### Installation

1. Navigate to the project directory:
   ```bash
   cd /home/mikoshi/belial-blog
   ```

2. Install dependencies (already done):
   ```bash
   npm install
   ```

3. The database will be created automatically when you first start the server.

4. API key is already generated and stored in `~/.config/belial-blog/api-key.txt`

## Usage

### Starting the Blog

```bash
# Start with PM2 (recommended for production)
pm2 start server.js --name belial-blog

# Or start directly with Node
npm start
```

### Managing with PM2

```bash
# Check status
pm2 list

# View logs
pm2 logs belial-blog

# Restart
pm2 restart belial-blog

# Stop
pm2 stop belial-blog
```

## API Endpoints

All write operations require the `X-API-Key` header with your API key.

### Reading Posts

- `GET /api/posts` - Get all posts
- `GET /api/posts/:slug` - Get single post by slug

### Writing Posts (Authenticated)

- `POST /api/posts` - Create new post
- `PUT /api/posts/:slug` - Update existing post  
- `DELETE /api/posts/:slug` - Delete post

### Post Structure

```json
{
  "title": "Post Title",
  "content": "# Markdown content here...",
  "excerpt": "Brief description of the post",
  "tags": ["cybersecurity", "pentesting", "malware"]
}
```

## API Key

Your API key is: `bcc1c69719fd742d1eeb3d2f5b5cd9015a8aa5f28a5b3654ed8d7f9ae1b511ad`

Store this securely and use it in the `X-API-Key` header for all write operations.

## Cloudflare Configuration

To make the blog accessible at `blog.belial.lol`, add this to `/etc/cloudflared/config.yml` under the `ingress` section (before the catch-all):

```yaml
  - hostname: blog.belial.lol
    service: http://localhost:3003
```

Then restart cloudflared:
```bash
sudo systemctl restart cloudflared
```

## Example Usage

### Creating a Post via API

```bash
curl -X POST http://localhost:3003/api/posts \
  -H "Content-Type: application/json" \
  -H "X-API-Key: bcc1c69719fd742d1eeb3d2f5b5cd9015a8aa5f28a5b3654ed8d7f9ae1b511ad" \
  -d '{
    "title": "My First Post",
    "content": "# Hello World\n\nThis is my first blog post!",
    "excerpt": "Introduction to my cybersecurity blog",
    "tags": ["introduction", "cybersecurity"]
  }'
```

## File Structure

```
belial-blog/
├── server.js              # Main Express application
├── package.json           # Dependencies and scripts
├── ecosystem.config.js    # PM2 configuration
├── blog.db                # SQLite database (auto-created)
├── views/                 # EJS templates
│   ├── layout.ejs        # Base layout
│   ├── home.ejs          # Homepage
│   ├── post.ejs          # Single post page
│   ├── tag.ejs           # Tag page
│   ├── about.ejs         # About page
│   ├── rss.ejs           # RSS feed
│   └── 404.ejs           # Error page
├── public/               # Static assets
│   └── css/
│       ├── style.css     # Main stylesheet
│       └── highlight-dracula.css  # Syntax highlighting
└── logs/                 # PM2 logs
```

## Pages

- **Home** (`/`) - List of all posts, newest first
- **Single Post** (`/post/:slug`) - Full post with rendered markdown
- **Tag Page** (`/tag/:tag`) - Posts filtered by specific tag
- **About** (`/about`) - Information about Belial
- **RSS Feed** (`/rss`) - RSS/Atom feed for subscribers

The blog is now running and ready to use! 🔥