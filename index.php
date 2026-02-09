<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DefSec | OWASP Top 10 Security SaaS</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #1a73e8;
            --primary-dark: #0d47a1;
            --secondary: #34a853;
            --dark: #202124;
            --light: #f8f9fa;
            --gray: #5f6368;
            --border: #dadce0;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', sans-serif;
            line-height: 1.6;
            color: var(--dark);
            background-color: var(--light);
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }
        
        /* Header */
        header {
            background-color: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            position: sticky;
            top: 0;
            z-index: 1000;
        }
        
        .nav-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 0;
        }
        
        .logo {
            display: flex;
            align-items: center;
            font-weight: 700;
            font-size: 1.8rem;
            color: var(--primary);
        }
        
        .logo span {
            color: var(--secondary);
        }
        
        .logo i {
            margin-right: 10px;
        }
        
        nav ul {
            display: flex;
            list-style: none;
        }
        
        nav li {
            margin-left: 30px;
        }
        
        nav a {
            text-decoration: none;
            color: var(--dark);
            font-weight: 500;
            transition: color 0.3s;
        }
        
        nav a:hover {
            color: var(--primary);
        }
        
        .cta-button {
            background-color: var(--primary);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        
        .cta-button:hover {
            background-color: var(--primary-dark);
        }
        
        /* Hero Section */
        .hero {
            padding: 100px 0;
            background: linear-gradient(135deg, #f5f7fa 0%, #e4e8f0 100%);
        }
        
        .hero-content {
            max-width: 800px;
            margin: 0 auto;
            text-align: center;
        }
        
        .hero h1 {
            font-size: 3.2rem;
            margin-bottom: 20px;
            line-height: 1.2;
        }
        
        .hero p {
            font-size: 1.2rem;
            color: var(--gray);
            margin-bottom: 40px;
            max-width: 700px;
            margin-left: auto;
            margin-right: auto;
        }
        
        .highlight {
            color: var(--primary);
            font-weight: 700;
        }
        
        /* OWASP Section */
        .owasp-section {
            padding: 100px 0;
            background-color: white;
        }
        
        .section-title {
            text-align: center;
            margin-bottom: 60px;
        }
        
        .section-title h2 {
            font-size: 2.5rem;
            margin-bottom: 15px;
        }
        
        .section-title p {
            color: var(--gray);
            max-width: 700px;
            margin: 0 auto;
        }
        
        .owasp-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 30px;
            margin-top: 40px;
        }
        
        .owasp-card {
            background: white;
            border-radius: 8px;
            padding: 30px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
            border-top: 4px solid var(--primary);
            transition: transform 0.3s, box-shadow 0.3s;
        }
        
        .owasp-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
        }
        
        .owasp-card i {
            font-size: 2.5rem;
            color: var(--primary);
            margin-bottom: 20px;
        }
        
        .owasp-card h3 {
            font-size: 1.4rem;
            margin-bottom: 15px;
        }
        
        .owasp-card p {
            color: var(--gray);
            margin-bottom: 20px;
        }
        
        /* Features Section */
        .features {
            padding: 100px 0;
            background-color: #f8f9fa;
        }
        
        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 30px;
            margin-top: 40px;
        }
        
        .feature-card {
            text-align: center;
            padding: 30px 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.03);
        }
        
        .feature-icon {
            width: 70px;
            height: 70px;
            background-color: rgba(26, 115, 232, 0.1);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 25px;
        }
        
        .feature-icon i {
            font-size: 1.8rem;
            color: var(--primary);
        }
        
        /* CTA Section */
        .cta-section {
            padding: 100px 0;
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
            text-align: center;
        }
        
        .cta-section h2 {
            font-size: 2.5rem;
            margin-bottom: 20px;
        }
        
        .cta-section p {
            max-width: 700px;
            margin: 0 auto 40px;
            font-size: 1.1rem;
            opacity: 0.9;
        }
        
        .cta-button-light {
            background-color: white;
            color: var(--primary);
            border: none;
            padding: 15px 30px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 1.1rem;
            cursor: pointer;
            transition: transform 0.3s, box-shadow 0.3s;
        }
        
        .cta-button-light:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
        }
        
        /* Footer */
        footer {
            background-color: var(--dark);
            color: white;
            padding: 60px 0 30px;
        }
        
        .footer-content {
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            margin-bottom: 40px;
        }
        
        .footer-column {
            flex: 1;
            min-width: 250px;
            margin-bottom: 30px;
        }
        
        .footer-column h3 {
            font-size: 1.2rem;
            margin-bottom: 25px;
            position: relative;
            padding-bottom: 10px;
        }
        
        .footer-column h3:after {
            content: '';
            position: absolute;
            left: 0;
            bottom: 0;
            width: 40px;
            height: 3px;
            background-color: var(--primary);
        }
        
        .footer-column ul {
            list-style: none;
        }
        
        .footer-column li {
            margin-bottom: 12px;
        }
        
        .footer-column a {
            color: #bdc1c6;
            text-decoration: none;
            transition: color 0.3s;
        }
        
        .footer-column a:hover {
            color: white;
        }
        
        .copyright {
            text-align: center;
            padding-top: 30px;
            border-top: 1px solid rgba(255,255,255,0.1);
            color: #bdc1c6;
            font-size: 0.9rem;
        }
        
        /* Responsive Design */
        @media (max-width: 768px) {
            .nav-container {
                flex-direction: column;
                padding: 20px 0;
            }
            
            nav ul {
                margin-top: 20px;
                flex-wrap: wrap;
                justify-content: center;
            }
            
            nav li {
                margin: 10px 15px;
            }
            
            .hero h1 {
                font-size: 2.5rem;
            }
            
            .section-title h2 {
                font-size: 2rem;
            }
        }
        
        /* Animation */
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .fade-in {
            animation: fadeIn 0.8s ease-out forwards;
        }
    </style>
</head>
<body>
    <!-- Header -->
    <header>
        <div class="container nav-container">
            <div class="logo">
                <i class="fas fa-shield-alt"></i>
                Def<span>Sec</span>
            </div>
            <nav>
                <ul>
                    <li><a href="#home">Home</a></li>
                    <li><a href="#owasp">OWASP Protection</a></li>
                    <li><a href="#features">Features</a></li>
                    <li><a href="#contact">Contact</a></li>
                </ul>
            </nav>
            <a href="http://localhost/defsec/v2/auth/login.php" 
   style="display: inline-block; 
          padding: 12px 24px; 
          background-color: #007bff; 
          color: #ffffff; 
          text-decoration: none; 
          border-radius: 6px; 
          font-weight: bold;">
   Get Started
</a>

        </div>
    </header>

    <!-- Hero Section -->
    <section class="hero" id="home">
        <div class="container hero-content fade-in">
            <h1>Enterprise-Grade Security Against <span class="highlight">OWASP Top 10</span> Vulnerabilities</h1>
            <p>DefSec provides comprehensive SaaS security solutions designed to protect your web applications from the most critical security risks identified by OWASP. Our automated platform integrates seamlessly into your development lifecycle.</p>
            <a href="http://localhost/defsec/v2/auth/login.php" 
   style="display: inline-block; 
          padding: 12px 24px; 
          background-color: #007bff; 
          color: #ffffff; 
          text-decoration: none; 
          border-radius: 6px; 
          font-weight: bold;">
   Get Started
</a>
        </div>
    </section>

    <!-- OWASP Section -->
    <section class="owasp-section" id="owasp">
        <div class="container">
            <div class="section-title">
                <h2>Comprehensive OWASP Top 10 Protection</h2>
                <p>Our SaaS platform provides automated security against all OWASP Top 10 vulnerabilities with continuous monitoring and real-time threat detection.</p>
            </div>
            
            <div class="owasp-grid">
                <div class="owasp-card">
                    <i class="fas fa-bug"></i>
                    <h3>Injection Protection</h3>
                    <p>Advanced SQL, NoSQL, and OS injection prevention with query validation and parameterization.</p>
                    <a href="#">Learn more →</a>
                </div>
                
                <div class="owasp-card">
                    <i class="fas fa-user-lock"></i>
                    <h3>Authentication Security</h3>
                    <p>Multi-factor authentication, secure session management, and credential stuffing protection.</p>
                    <a href="#">Learn more →</a>
                </div>
                
                <div class="owasp-card">
                    <i class="fas fa-exposure"></i>
                    <h3>Sensitive Data Exposure</h3>
                    <p>Automatic data encryption, tokenization, and compliance with data protection regulations.</p>
                    <a href="#">Learn more →</a>
                </div>
                
                <div class="owasp-card">
                    <i class="fas fa-cogs"></i>
                    <h3>XXE Prevention</h3>
                    <p>XML external entity attack prevention with secure parsing configurations and schema validation.</p>
                    <a href="#">Learn more →</a>
                </div>
                
                <div class="owasp-card">
                    <i class="fas fa-shield-check"></i>
                    <h3>Access Control</h3>
                    <p>Role-based access control (RBAC) with policy enforcement and privilege escalation prevention.</p>
                    <a href="#">Learn more →</a>
                </div>
                
                <div class="owasp-card">
                    <i class="fas fa-sliders-h"></i>
                    <h3>Security Misconfiguration</h3>
                    <p>Automated configuration scanning and hardening recommendations for all stack components.</p>
                    <a href="#">Learn more →</a>
                </div>
            </div>
        </div>
    </section>

    <!-- Features Section -->
    <section class="features" id="features">
        <div class="container">
            <div class="section-title">
                <h2>Why Choose DefSec SaaS Platform</h2>
                <p>Our security-as-a-service platform delivers enterprise-grade protection with minimal setup and maintenance.</p>
            </div>
            
            <div class="features-grid">
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-cloud"></i>
                    </div>
                    <h3>Cloud-Native</h3>
                    <p>Built for modern cloud environments with auto-scaling and high availability.</p>
                </div>
                
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-bolt"></i>
                    </div>
                    <h3>Real-Time Protection</h3>
                    <p>Continuous monitoring and immediate threat response with near-zero latency.</p>
                </div>
                
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-code"></i>
                    </div>
                    <h3>DevSecOps Integration</h3>
                    <p>Seamlessly integrates into CI/CD pipelines with APIs and plugins for all major tools.</p>
                </div>
                
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-chart-line"></i>
                    </div>
                    <h3>Compliance Dashboard</h3>
                    <p>Real-time compliance reporting for SOC2, ISO 27001, GDPR, and other standards.</p>
                </div>
            </div>
        </div>
    </section>

    <!-- CTA Section -->
    <section class="cta-section">
        <div class="container">
            <h2>Ready to Secure Your Applications?</h2>
            <p>Join hundreds of companies who trust DefSec to protect their applications against OWASP Top 10 vulnerabilities. Start your free 14-day trial today.</p>
            <button class="cta-button-light">Start Free Trial</button>
        </div>
    </section>

    <!-- Footer -->
    <footer id="contact">
        <div class="container">
            <div class="footer-content">
                <div class="footer-column">
                    <div class="logo" style="color: white; margin-bottom: 25px;">
                        <i class="fas fa-shield-alt"></i>
                        Def<span>Sec</span>
                    </div>
                    <p>Enterprise-grade SaaS security platform protecting against OWASP Top 10 vulnerabilities with automated, real-time threat prevention.</p>
                </div>
                
                <div class="footer-column">
                    <h3>Product</h3>
                    <ul>
                        <li><a href="#">OWASP Protection</a></li>
                        <li><a href="#">API Security</a></li>
                        <li><a href="#">Compliance</a></li>
                        <li><a href="#">Pricing</a></li>
                    </ul>
                </div>
                
                <div class="footer-column">
                    <h3>Company</h3>
                    <ul>
                        <li><a href="#">About Us</a></li>
                        <li><a href="#">Customers</a></li>
                        <li><a href="#">Careers</a></li>
                        <li><a href="#">Blog</a></li>
                    </ul>
                </div>
                
                <div class="footer-column">
                    <h3>Contact</h3>
                    <ul>
                        <li><a href="#">support@defsec.com</a></li>
                        <li><a href="#">+1 (555) 123-4567</a></li>
                        <li><a href="#">Security Boulevard, Suite 500</a></li>
                        <li><a href="#">San Francisco, CA 94107</a></li>
                    </ul>
                </div>
            </div>
            
            <div class="copyright">
                <p>&copy; 2023 DefSec Security Solutions. All rights reserved. | <a href="#" style="color: #bdc1c6;">Privacy Policy</a> | <a href="#" style="color: #bdc1c6;">Terms of Service</a></p>
            </div>
        </div>
    </footer>

    <script>
        // Smooth scrolling for navigation links
        document.querySelectorAll('nav a, .cta-button, .cta-button-light').forEach(anchor => {
            anchor.addEventListener('click', function(e) {
                // For buttons that aren't links, skip smooth scrolling
                if(this.tagName === 'BUTTON' && !this.getAttribute('href')) {
                    return;
                }
                
                e.preventDefault();
                const targetId = this.getAttribute('href');
                
                if(targetId && targetId.startsWith('#')) {
                    const targetElement = document.querySelector(targetId);
                    if(targetElement) {
                        window.scrollTo({
                            top: targetElement.offsetTop - 80,
                            behavior: 'smooth'
                        });
                    }
                }
            });
        });
        
        // Simple animation on scroll
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };
        
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if(entry.isIntersecting) {
                    entry.target.classList.add('fade-in');
                }
            });
        }, observerOptions);
        
        // Observe elements for animation
        document.querySelectorAll('.owasp-card, .feature-card').forEach(el => {
            observer.observe(el);
        });
        
        // CTA button interactions
        document.querySelectorAll('.cta-button, .cta-button-light').forEach(button => {
            button.addEventListener('click', function() {
                if(this.textContent === 'Get Started' || this.textContent === 'Start Free Trial') {
                    alert('Thank you for your interest in DefSec! Our team will contact you shortly to set up your free trial.');
                }
            });
        });
    </script>
</body>
</html>