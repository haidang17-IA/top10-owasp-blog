
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>My OWASP Blog</title>
  <link rel="stylesheet" href="{{ '/assets/css/custom.css' | relative_url }}">
</head>
<body>
  <!-- Clean Slider with Curved Background -->
  <section class="curved-slider">
    <div class="slides">
      <div class="slide active">
        <h1> Welcome to My OWASP Blog</h1>
        <p>Explore vulnerabilities, payloads, and knowledge from PortSwigger & OWASP Top 10</p>
      </div>
      <div class="slide">
        <h1> SQL Injection</h1>
        <p>Learn about extracting hidden data, bypassing logic, and attacking databases</p>
      </div>
      <div class="slide">
        <h1> XXE, XSS, and more</h1>
        <p>Understand how common web vulnerabilities work and how to prevent them</p>
      </div>
    </div>

    <!-- Navigation arrows -->
    <div class="slider-nav">
      <button onclick="prevSlide()">◀</button>
      <button onclick="nextSlide()">▶</button>
    </div>

    <!-- Curved SVG background -->
    <svg viewBox="0 0 1440 320" class="curve">
      <path fill="#f3f4f6" fill-opacity="1"
        d="M0,192L60,176C120,160,240,128,360,138.7C480,149,600,203,720,218.7C840,235,960,213,1080,192C1200,171,1320,149,1380,138.7L1440,128L1440,0L1380,0C1320,0,1200,0,1080,0C960,0,840,0,720,0C600,0,480,0,360,0C240,0,120,0,60,0L0,0Z">
      </path>
    </svg>
  </section>

  <!-- Main content -->
  <main>
    <section style="padding: 50px; max-width: 800px; margin: auto;">
      <h2> Latest Posts</h2>
      <p>This blog documents my journey in understanding web application security, starting with Injection vulnerabilities from PortSwigger and OWASP Top 10.</p>
    </section>
  </main>

  <!-- Slider script -->
  <script>
    document.addEventListener("DOMContentLoaded", function () {
      let currentSlide = 0;
      const slides = document.querySelectorAll('.slide');

      function showSlide(index) {
        slides.forEach((slide, i) => {
          slide.classList.toggle('active', i === index);
        });
      }

      function nextSlide() {
        currentSlide = (currentSlide + 1) % slides.length;
        showSlide(currentSlide);
      }

      function prevSlide() {
        currentSlide = (currentSlide - 1 + slides.length) % slides.length;
        showSlide(currentSlide);
      }

      // Gán hàm vào global scope
      window.nextSlide = nextSlide;
      window.prevSlide = prevSlide;

      setInterval(nextSlide, 6000);
    });
  </script>
</body>
</html>
