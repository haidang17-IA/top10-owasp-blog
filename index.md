---
layout: default
---

<!-- Background động -->
<div id="particles-js"></div>

<style>
  #particles-js {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    z-index: -1;
  }
</style>

<!-- Phần header với hiệu ứng gradient -->
<div class="hero">
  <div class="hero-text">
    <h1> Welcome to My OWASP Blog</h1>
    <p>Explore vulnerabilities, payloads, and security knowledge from PortSwigger & OWASP Top 10</p>
  </div>
</div>

<!-- Danh sách bài viết -->
<div class="container">
  <div class="posts-grid">
    {% for post in site.posts %}
    <div class="post-card">
      <h2>📝 <a href="{{ post.url | relative_url }}">{{ post.title }}</a></h2>
      <p class="date">🕒 {{ post.date | date: "%B %d, %Y" }}</p>
      <p>{{ post.excerpt | strip_html | truncatewords: 25 }}</p>
      <a href="{{ post.url | relative_url }}" class="read-more">➤ Read more</a>
    </div>
    {% endfor %}
  </div>
</div>

<!-- Particles.js -->
<script src="https://cdn.jsdelivr.net/npm/particles.js@2.0.0/particles.min.js"></script>
<script>
  particlesJS("particles-js", {
    particles: {
      number: { value: 60 },
      size: { value: 2.5 },
      color: { value: "#00bcd4" },
      line_linked: {
        enable: true,
        distance: 140,
        color: "#00bcd4",
        opacity: 0.5,
        width: 1
      },
      move: { enable: true, speed: 2 }
    }
  });
</script>

<!-- Scroll Reveal -->
<script src="https://unpkg.com/scrollreveal"></script>
<script>
  ScrollReveal().reveal('.post-card', {
    origin: 'bottom',
    distance: '40px',
    duration: 800,
    delay: 100,
    easing: 'ease-out',
    reset: false
  });
</script>
