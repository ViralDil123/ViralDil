
/* ViralDil — Homepage
   Frontend UI only. Backend features will be connected later.
*/

(() => {
  'use strict';

  const app = document.getElementById('app');

  if (!app) return;

  const categories = [
    {
      name: 'Emotional',
      icon: '💜',
      description: 'Stories that touch the heart'
    },
    {
      name: 'Romance',
      icon: '🌹',
      description: 'Love, memories and moments'
    },
    {
      name: 'Funny',
      icon: '😂',
      description: 'A little laughter every day'
    },
    {
      name: 'AI Stories',
      icon: '✨',
      description: 'Creative AI-made storytelling'
    },
    {
      name: 'Trending',
      icon: '🔥',
      description: 'Discover popular videos'
    },
    {
      name: 'Entertainment',
      icon: '🎬',
      description: 'Fresh short-form entertainment'
    }
  ];

  const categoryCards = categories.map(item => `
    <a class="card category-card"
       href="discover.html?category=${encodeURIComponent(item.name)}">

      <div class="art">${item.icon}</div>

      <span class="tag">Explore</span>

      <h3>${item.name}</h3>

      <p class="muted">${item.description}</p>

    </a>
  `).join('');

  app.innerHTML = `

    <header class="top wrap">

      <a class="brand" href="index.html">
        Viral<span>Dil</span>
      </a>

      <nav class="nav">
        <a href="index.html">Home</a>
        <a href="discover.html">Discover</a>
        <a href="watch.html">Watch</a>
      </nav>

      <div style="display:flex;gap:9px;align-items:center">

        <a class="btn secondary" href="login.html">
          Log in
        </a>

        <a class="btn" href="signup.html">
          Join ViralDil
        </a>

      </div>

    </header>

    <main>

      <section class="hero wrap">

        <div>

          <p class="eyebrow">
            A world of stories in every scroll
          </p>

          <h1>
            Feel it.
            <span class="gradient">Watch it.</span>
            <br>
            Share the moment.
          </h1>

          <p class="muted">
            Discover emotional stories, romance, comedy
            and creative short videos — all in one place.
            Your next favourite moment is just a scroll away.
          </p>

          <div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:24px">

            <a class="btn" href="discover.html">
              Explore videos
            </a>

            <a class="btn secondary" href="signup.html">
              Become a creator
            </a>

          </div>

          <p class="muted" style="font-size:12px;margin-top:16px">
            Short videos up to 10 minutes.
          </p>

        </div>

        <div class="showcase">
          ▶️
        </div>

      </section>

      <section class="section wrap">

        <div class="head">

          <div>

            <p class="eyebrow">
              Find your feeling
            </p>

            <h2 style="font:700 30px Outfit;margin:8px 0">
              Explore categories
            </h2>

          </div>

          <a class="btn secondary" href="discover.html">
            See all
          </a>

        </div>

        <div class="grid">
          ${categoryCards}
        </div>

      </section>

      <section class="section wrap">

        <div class="panel"
             style="display:flex;align-items:center;justify-content:space-between;gap:22px;flex-wrap:wrap">

          <div style="max-width:620px">

            <p class="eyebrow">
              Your creativity belongs here
            </p>

            <h2 style="font:700 28px Outfit;margin:8px 0">
              Have a story to share?
            </h2>

            <p class="muted">
              Create an account to get started.
              Uploading and publishing will become available
              when creator services and review systems are connected.
            </p>

          </div>

          <a class="btn" href="signup.html">
            Create your account
          </a>

        </div>

      </section>

    </main>

    <footer class="footer">

      <div class="wrap"
           style="display:flex;justify-content:space-between;gap:14px;flex-wrap:wrap">

        <span>© ${new Date().getFullYear()} ViralDil</span>

        <span>Short videos. Real feelings.</span>

      </div>

    </footer>

  `;
const splash = document.createElement('div');
splash.className = 'viraldil-splash';
splash.innerHTML = '<img src="assets/images/viraldil-splash.png" alt="ViralDil">';
document.body.appendChild(splash);

setTimeout(() => splash.remove(), 2500);
})();
