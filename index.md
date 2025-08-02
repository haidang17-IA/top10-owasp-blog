---
layout: default
title: "OWASP Top 10 Blog"
---

<!-- Hero Section -->
<section class="hero">
  <div class="hero-content">
    <h1>OWASP Top 10 Blog</h1>
    <p>Learn, practice, and share knowledge about the OWASP Top 10 vulnerabilities with real-world examples and labs.</p>
    <a href="#latest-posts" class="btn-primary">Explore Now</a>
  </div>
</section>

<!-- Latest Posts -->
<section id="latest-posts" class="latest-posts">
  <h2>Latest Posts</h2>
  <div class="post-grid">
    {% for post in site.posts limit:3 %}
      <div class="post-card">
        <h3><a href="{{ post.url }}">{{ post.title }}</a></h3>
        <p>{{ post.excerpt | strip_html | truncate: 120 }}</p>
        <a href="{{ post.url }}" class="btn-secondary">Read More</a>
      </div>
    {% endfor %}
  </div>
</section>
