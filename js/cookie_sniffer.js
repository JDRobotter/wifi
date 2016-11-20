/*
<html><head></head>
<body>
<p>Hey</p>
<script>
// */
var domains = [
  "google.com",
  "youtube.com",
  "facebook.com",
  "baidu.com",
  "yahoo.com",
  "amazon.com",
  "wikipedia.org",
  "qq.com",
  "google.co.in",
  "twitter.com",
  "live.com",
  "taobao.com",
  "msn.com",
  "sina.com.cn",
  "yahoo.co.jp",
  "google.co.jp",
  "linkedin.com",
  "weibo.com",
  "bing.com",
  "yandex.ru",
  "vk.com",
  "hao123.com",
  "instagram.com",
  "ebay.com",
  "google.de",
  "amazon.co.jp",
  "360.cn",
  "tmall.com",
  "mail.ru",
  "pinterest.com",
  "google.co.uk",
  "google.ru",
  "reddit.com",
  "netflix.com",
  "t.co",
  "google.com.br",
  "sohu.com",
  "google.fr",
  "paypal.com",
  "microsoft.com",
  "wordpress.com",
  "google.it",
  "google.es",
  "blogspot.com",
  "tumblr.com",
  "onclickads.net",
  "apple.com",
  "imgur.com",
  "ok.ru",
  "gmw.cn",
  "xvideos.com",
  "stackoverflow.com",
  "aliexpress.com",
  "google.com.hk",
  "imdb.com",
  "google.com.mx",
  "fc2.com",
  "ask.com",
  "amazon.de",
  "google.com.tr",
  "google.ca",
  "rakuten.co.jp",
  "tianya.cn",
  "alibaba.com",
  "office.com",
  "diply.com",
  "pornhub.com",
  "google.co.id",
  "soso.com",
  "github.com",
  "craigslist.org",
  "chinadaily.com.cn",
  "go.com",
  "xinhuanet.com",
  "pixnet.net",
  "nicovideo.jp",
  "amazon.co.uk",
  "amazon.in",
  "bongacams.com",
  "outbrain.com",
  "cnn.com",
  "cntv.cn",
  "googleusercontent.com",
  "blogger.com",
  "kat.cr",
  "naver.com",
  "google.pl",
  "google.com.au",
  "jd.com",
  "coccoc.com",
  "dropbox.com",
  "china.com",
  "xhamster.com",
  "360.com",
  "adobe.com",
  "haosou.com",
  "sogou.com",
  "microsoftonline.com",
  "nytimes.com",
  "whatsapp.com",
  "chase.com",
  "flipkart.com",
  "alipay.com",
  "163.com",
  "booking.com",
  "google.com.eg",
  "bbc.co.uk",
  "espn.go.com",
  "adnetworkperformance.com",
  "amazon.cn",
  "google.com.pk",
  "google.com.sa",
  "youth.cn",
  "wikia.com",
  "youku.com",
  "google.co.th",
  "indiatimes.com",
  "china.com.cn",
  "livedoor.jp",
  "google.com.ar",
  "google.com.tw",
  "ebay.co.uk",
  "ebay.de",
  "google.co.kr",
  "wittyfeed.com",
  "dailymotion.com",
  "quora.com",
  "cnzz.com",
  "bankofamerica.com",
  "adf.ly",
  "bbc.com",
  "amazonaws.com",
  "twitch.tv",
  "google.nl",
  "xnxx.com",
  "popads.net",
  "dailymail.co.uk",
  "buzzfeed.com",
  "huffingtonpost.com",
  "tudou.com",
  "ettoday.net",
  "wellsfargo.com",
  "zillow.com",
  "globo.com",
  "so.com",
  "etsy.com",
  "dmm.co.jp",
  "ameblo.jp",
  "detail.tmall.com",
  "walmart.com",
  "uol.com.br",
  "indeed.com",
  "yelp.com",
  "aol.com",
  "avito.ru",
  "blogspot.in",
  "zhihu.com",
  "google.gr",
  "soundcloud.com",
  "detik.com",
  "txxx.com",
  "slideshare.net",
  "cnet.com",
  "google.co.za",
  "weather.com",
  "directrev.com",
  "google.com.ua",
  "bilibili.com",
  "theguardian.com",
  "espncricinfo.com",
  "theladbible.com",
  "kakaku.com",
  "vice.com",
  "goo.ne.jp",
  "naver.jp",
  "taboola.com",
  "flickr.com",
  "salesforce.com",
  "stackexchange.com",
  "washingtonpost.com",
  "gfycat.com",
  "mediafire.com",
  "amazon.it",
  "foxnews.com",
  "google.com.ng",
  "taringa.net",
  "tripadvisor.com",
  "google.cn",
  "redtube.com",
  "uptodown.com",
  "amazon.fr",
  "target.com",
  "leboncoin.fr",
  "forbes.com",
  "daum.net",
  "godaddy.com",
  "feedly.com",
  "google.com.co",
  "imzog.com",
  "softonic.com",
  "liveadexchanger.com",
  "google.com.sg",
  "bp.blogspot.com",
  "tradeadexchange.com",
  "51.la",
  "snapdeal.com",
  "ikea.com",
  "hclips.com",
  "orange.fr",
  "web.de",
  "youm7.com",
  "vimeo.com",
  "github.io",
  "onlinesbi.com",
  "ifeng.com",
  "babytree.com",
  "nih.gov",
  "google.ro",
  "youporn.com",
  "comcast.net",
  "9gag.com",
  "zol.com.cn",
  "force.com",
  "steamcommunity.com",
  "americanexpress.com",
  "udn.com",
  "google.be",
  "tribunnews.com",
  "pixiv.net",
  "gmx.net",
  "intuit.com",
  "torrentz.eu",
  "secureserver.net",
  "rdsa2012.com",
  "thepiratebay.se",
  "reimageplus.com",
  "mozilla.org",
  "steampowered.com",
  "about.com",
  "wikihow.com",
  "allegro.pl",
  "wix.com",
  "google.com.ph",
  "livejournal.com",
  "1688.com",
  "homedepot.com",
  "gamer.com.tw",
  "hdfcbank.com",
  "akamaihd.net",
  "xuite.net",
  "capitalone.com",
  "skype.com",
  "bestbuy.com",
  "usps.com",
  "putlocker.is",
  "w3schools.com",
  "shutterstock.com",
  "xywy.com",
  "iqiyi.com",
  "groupon.com",
  "ruten.com.tw",
  "google.at",
  "google.co.ve",
  "deviantart.com",
  "hulu.com",
  "bitauto.com",
  "mega.nz",
  "xfinity.com",
  "onet.pl",
  "google.com.pe",
  "slickdeals.net",
  "icicibank.com",
  "upornia.com",
  "t-online.de",
  "files.wordpress.com",
  "speedtest.net",
  "huanqiu.com",
  "seznam.cz",
  "nametests.com",
  "youtube-mp3.org",
  "pandora.com",
  "bet365.com",
  "blastingnews.com",
  "archive.org",
  "caijing.com.cn",
  "businessinsider.com",
  "blog.jp",
  "eksisozluk.com",
  "amazon.es",
  "weebly.com",
  "google.se",
  "wikimedia.org",
  "ups.com",
  "csdn.net",
  "rambler.ru",
  "google.pt",
  "google.ae",
  "ebay-kleinanzeigen.de",
  "goodreads.com",
  "spotify.com",
  "webtretho.com",
  "wordpress.org",
  "1905.com",
  "wp.pl",
  "google.ch",
  "doorblog.jp",
  "mama.cn",
  "google.dz",
  "usatoday.com",
  "samsung.com",
  "ndtv.com",
  "popcash.net",
  "onedio.com",
  "cnnic.cn",
  "liputan6.com",
  "39.net",
  "terraclicks.com",
  "siteadvisor.com",
  "telegraph.co.uk",
  "fedex.com",
  "hp.com",
  "rediff.com",
  "wordreference.com",
  "ltn.com.tw",
  "webmd.com",
  "51yes.com",
  "sberbank.ru",
  "abs-cbn.com",
  "accuweather.com",
  "kaskus.co.id",
  "2ch.net",
  "google.co.il",
  "varzesh3.com",
  "twimg.com",
  "milliyet.com.tr",
  "doubleclick.net",
  "att.com",
  "irctc.co.in",
  "fbcdn.net",
  "hurriyet.com.tr",
  "sourceforge.net",
  "icloud.com",
  "loading-delivery2.com",
  "sabah.com.tr",
  "thesaurus.com",
  "google.hu",
  "themeforest.net",
  "google.cl",
  "gizmodo.com",
  "kompas.com",
  "dell.com",
  "ontests.me",
  "paytm.com",
  "enet.com.cn",
  "eastday.com",
  "verizonwireless.com",
  "kapanlagi.com",
  "mailchimp.com",
  "google.cz",
  "bloomberg.com",
  "mercadolivre.com.br",
  "chaturbate.com",
  "mashable.com",
  "zendesk.com",
  "addthis.com",
  "google.ie",
  "digikala.com",
  "badoo.com",
  "gsmarena.com",
  "trello.com",
  "livejasmin.com",
  "sahibinden.com",
  "impress.co.jp",
  "urdupoint.com",
  "bukalapak.com",
  "life.tw",
  "merdeka.com",
  "slack.com",
  "media.tumblr.com",
  "cricbuzz.com",
  "chaoshi.tmall.com",
  "mystart.com",
  "adidas.tmall.com",
  "hotstar.com",
  "watsons.tmall.com",
  "medium.com",
  "oracle.com",
  "kinogo.co",
  "jabong.com",
  "ign.com",
  "wsj.com",
  "douyutv.com",
  "buzzlie.com",
  "avg.com",
  "yandex.ua",
  "macys.com",
  "blogfa.com",
  "pinimg.com",
  "savefrom.net",
  "ilyke.co",
  "tube8.com",
  "citi.com",
  "lowes.com",
  "doublepimp.com",
  "livedoor.biz",
  "blackboard.com",
  "nownews.com",
  "reuters.com",
  "naukri.com",
  "eyny.com",
  "olx.pl",
  "nyaa.se",
  "roblox.com",
  "airbnb.com",
  "baike.com",
  "dmm.com",
  "taleo.net",
  "cbssports.com",
  "ebay.in",
  "expedia.com",
  "libero.it",
  "kohls.com",
  "evernote.com",
  "adplxmd.com",
  "kinopoisk.ru",
  "bild.de",
  "sharepoint.com",
  "spiegel.de",
  "kwejk.pl",
  "irs.gov",
  "livedoor.com",
  "google.fi",
  "thesportbible.com",
  "hootsuite.com",
  "engadget.com",
  "amazon.ca",
  "bhaskar.com",
  "friv.com",
  "playstation.com",
  "giphy.com",
  "haber7.com",
  "likes.com",
  "mi.com",
  "ameba.jp",
  "scribd.com",
  "google.no",
  "ci123.com",
  "shopify.com",
  "ancestry.com",
  "tistory.com",
  "tokopedia.com",
  "google.sk",
  "hm.com",
  "mobile.de",
  "box.com",
  "17ok.com",
  "infusionsoft.com",
  "battle.net",
  "tabelog.com",
  "streamcloud.eu",
  "newegg.com",
  "patch.com",
  "aparat.com",
  "allrecipes.com",
  "instructure.com",
  "nike.com",
  "ebay.it",
  "realtor.com",
  "rbc.ru",
  "youdao.com",
  "google.dk",
  "thefreedictionary.com",
  "4shared.com",
  "quikr.com",
  "conservativetribune.com",
  "hespress.com",
  "lifehacker.com",
  "billdesk.com",
  "fidelity.com",
  "nbcnews.com",
  "gearbest.com",
  "messenger.com",
  "discovercard.com",
  "repubblica.it",
  "free.fr",
  "elpais.com",
  "cnblogs.com",
  "cloudfront.net",
  "yallakora.com",
  "npr.org",
  "surveymonkey.com",
  "asos.com",
  "gap.com",
  "stumbleupon.com",
  "freepik.com",
  "theverge.com",
  "wunderground.com",
  "list-manage.com",
  "japanpost.jp",
  "nifty.com",
  ];

function add_image(host) {
  var url='http://'+host+'/'+Math.random()+'/leaking_cookies';
  var img =  document.createElement('img');
  document.body.appendChild(img);
  img.src = url
}

function add_iframe(host) {
  var url= 'http://'+host+'/'+Math.random()+'/leaking_cookies';
  var iframe = document.createElement('iframe');
  iframe.src = url;
  document.body.appendChild(iframe);

  iframe.style.visibility = 'hidden';
  iframe.style.display = 'none';
}

for (i in domains) {
  var dom = domains[i];
  add_iframe(dom);
  console.log(dom);
}

</script>
</body>
</html>
*/
