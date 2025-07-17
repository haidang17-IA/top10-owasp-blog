source "https://rubygems.org"

# 👉 Dùng GitHub Pages gem để tự quản lý đúng Jekyll version
gem "github-pages", group: :jekyll_plugins

# 👉 Các plugin được GitHub Pages hỗ trợ (bạn có thể giữ lại)
group :jekyll_plugins do
  gem "jekyll-feed", "~> 0.12"
end

# 👉 Phần hỗ trợ Windows & JRuby
platforms :mingw, :x64_mingw, :mswin, :jruby do
  gem "tzinfo", ">= 1", "< 3"
  gem "tzinfo-data"
end

gem "wdm", "~> 0.1", platforms: [:mingw, :x64_mingw, :mswin]
gem "http_parser.rb", "~> 0.6.0", platforms: [:jruby]
