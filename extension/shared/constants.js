// PhishGuard v3.0 — Shared Constants

const BLOCK_THRESHOLD = 50;

const TRUSTED_DOMAINS = new Set([
  'google.com','www.google.com','mail.google.com','docs.google.com','drive.google.com',
  'accounts.google.com','youtube.com','github.com','gitlab.com','linkedin.com',
  'microsoft.com','office.com','live.com','outlook.com','office365.com','bing.com',
  'yahoo.com','wikipedia.org','reddit.com','stackoverflow.com','npmjs.com','pypi.org',
  'cloudflare.com','amazonaws.com','azure.com','apple.com','icloud.com','twitter.com',
  'x.com','facebook.com','instagram.com','whatsapp.com','telegram.org','discord.com',
  'slack.com','zoom.us','notion.so','anthropic.com','claude.ai','openai.com',
  'chatgpt.com','paypal.com','stripe.com','shopify.com','amazon.com','netflix.com',
  'spotify.com','adobe.com','dropbox.com','atlassian.com','jira.com','trello.com',
  'figma.com','canva.com','hubspot.com','salesforce.com','twilio.com','sendgrid.com',
  'vercel.app','netlify.app','heroku.com','render.com','railway.app','supabase.com',
  'firebase.google.com','auth0.com','okta.com','cloudinary.com','akamai.com',
  'allegro.pl','allegrolokalnie.pl','olx.pl','olx.com','caniphish.com'
]);

const TRUSTED_TLDS = new Set([
  '.edu','.edu.in','.ac.in','.ac.uk','.gov','.gov.in','.gov.uk','.mil','.int',
  '.org','.co.uk','.com.au','.co.in','.nic.in'
]);

const COLLEGE_KEYWORDS = ['ssmrv','nmkrv','rvce','rvpu','rvengg','vtu','pes'];

const HIGH_RISK_TLDS = new Set([
  '.xyz','.top','.pw','.cc','.club','.tk','.ml','.sbs','.icu','.vip',
  '.gq','.cf','.ga','.work','.racing','.date','.download','.cricket',
  '.lat','.lol','.cyou','.bond','.hair','.rest','.monster','.fun',
  '.cfd','.digital','.click','.live','.world','.shop','.store'
]);

const MEDIUM_RISK_TLDS = new Set(['.pro','.online','.site','.info','.biz','.ws','.mobi']);

const FREE_HOSTING = new Set([
  '000webhostapp.com','weebly.com','wixsite.com','wixstudio.com','wix.com',
  'blogspot.com','wordpress.com','glitch.me','pages.dev','web.app',
  'firebaseapp.com','surge.sh','tiiny.site'
]);

const URL_SHORTENERS = new Set([
  'bit.ly','tinyurl.com','t.co','ow.ly','buff.ly','rebrand.ly',
  'short.io','cutt.ly','is.gd','tiny.cc','rb.gy'
]);

const TOP_BRANDS = [
  'google','youtube','facebook','amazon','microsoft','apple','instagram','twitter',
  'linkedin','netflix','paypal','github','reddit','wikipedia','yahoo','bing',
  'whatsapp','telegram','discord','dropbox','spotify','adobe','stripe','shopify',
  'chase','wellsfargo','bankofamerica','citibank','hsbc','barclays','ebay',
  'walmart','fedex','ups','dhl','usps',
  'allegro','allegrolokalnie','olx','mercadolibre','rakuten','flipkart',
  'snapdeal','paytm','phonepe','lazada','tokopedia','shopee','grab','gojek',
  'sbi','icici','hdfc','axis','kotak','santander','nationwide','lloyds','natwest'
];

const FAKE_CCTLD_PATTERNS = [
  '.pl-','.uk-','.de-','.fr-','.it-','.es-','.ru-','.cn-','.jp-',
  '.au-','.ca-','.in-','.br-','.nl-','.se-','.no-','.fi-','.dk-'
];

const SENSITIVITY_THRESHOLDS = { STRICT: 35, BALANCED: 50, RELAXED: 65 };

const ENTROPY_HIGH = 3.8;
const ENTROPY_MED  = 3.2;
const CVR_THRESHOLD = 3.5;
const NUMERIC_RATIO_THRESHOLD = 0.35;

const OWASP = {
  CREDENTIAL: 'OWASP A02:Cryptographic Failures',
  ACCESS:     'OWASP A01:Broken Access Control',
  DESIGN:     'OWASP A04:Insecure Design',
  INTEGRITY:  'OWASP A08:Software & Data Integrity Failures',
  INJECTION:  'OWASP A03:Injection',
  SSRF:       'OWASP A10:Server-Side Request Forgery'
};

// Expanded urgency phrases — covers CanIPhish, real-world phishing, and social engineering
const URGENCY_PHRASES = [
  // Account suspension/closure
  'your account has been suspended','your account will be closed',
  'your account has been compromised','your account is at risk',
  'reactivate your account','account verification required',
  // Verify/confirm actions
  'verify immediately','verify your identity','verify your email',
  'confirm your identity','confirm your information','confirm personal information',
  'click here to confirm','failure to verify',
  // Unauthorized/suspicious access
  'unauthorized access detected','unauthorized access',
  'unusual sign-in activity','unusual activity detected','unusual activity',
  'suspicious login detected','suspicious login','suspicious activity detected',
  'someone tried to sign in','login attempt blocked','login attempt',
  'new device logged in','new sign-in detected',
  // Password
  'your password has expired','password will expire','upcoming password expiry',
  'reset your password now','update your password','confirm your password',
  // Urgency/time pressure
  'immediate action required','act now','act immediately',
  'respond immediately','urgent action','action required',
  'expires in 24 hours','expires today','within 24 hours',
  'limited time','last chance','final notice','final warning',
  // Security alerts
  'security alert','security warning','we detected suspicious',
  'we have detected','strange account activity',
  // Financial
  'update your billing','update your payment','payment failed',
  'payment declined','billing information required',
  'your invoice is attached','invoice overdue',
  // Prize/reward social engineering
  'claim your prize','you have been selected','you are eligible',
  'congratulations you have won','you won',
  // Delivery
  'your package could not be delivered','delivery failed',
  'package on hold','customs fee required','shipment requires',
  // New access/system
  'new system access','access request raised',
  // IT/helpdesk
  'perform an urgent software update','urgent software update',
  'enable macros to view','enable content to view',
];
