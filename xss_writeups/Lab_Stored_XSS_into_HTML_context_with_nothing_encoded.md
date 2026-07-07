# Lab: Stored XSS into HTML context with nothing encoded

> **Author**: Songül Kızılay Özügürler
> **Published**: Apr 30, 2026

---

Member-only story

![Songül Kızılay Özügürler](https://miro.medium.com/v2/resize:fill:64:64/1*OSA118PJ-81kc9jpqeicyw.png)

6

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*SBXqZYf0lEBExkiKm2SHAw.png)

Şöyle düşün: Masum bir yorum alanı… herkes düşüncesini yazıyor, paylaşıyor. Ama arka planda hiçbir filtre yoksa? İşte tam burada Stored XSS sahneye giriyor.

Bu lab’de karşımıza çıkan senaryo tam olarak bu. Blog altına bırakılan yorumlar herhangi bir encoding ya da sanitization işleminden geçmeden doğrudan sayfaya basılıyor. Yani senin yazdığın şey sadece bir yorum değil — potansiyel olarak çalışan bir payload.

Ben de bu noktada klasik ama etkili bir yaklaşım izledim: yorum alanını sadece metin yazmak için değil, JavaScript çalıştırmak için kullandım. Amaç basit — blog görüntülendiğinde tetiklenecek bir alert() fonksiyonu.

Bu tarz zafiyetler teoride “basit” görünse de gerçek hayatta etkisi baya kritik. Çünkü payload bir kere sisteme girince, o sayfayı ziyaret eden herkesi etkileyebiliyor. Yani reflected değil, kalıcı bir tehditten bahsediyoruz.

Şimdi adım adım nasıl çalıştığını anlatayım

![image](https://miro.medium.com/v2/resize:fit:700/1*_ILLNw1lK3ypf1STSiFtsw.png)

İlk olarak blog postunun altındaki yorum alanını test etmeye başladım. Burada dikkatimi çeken şey, girilen input’un herhangi bir filtreleme ya da encoding işleminden geçip geçmediğiydi. Bunu hızlıca…



---
*Original URL: [https://medium.com/@songulkizilay/lab-stored-xss-into-html-context-with-nothing-encoded-1eb5f6e9c875?source=search_post---------30-----------------------------------](https://medium.com/@songulkizilay/lab-stored-xss-into-html-context-with-nothing-encoded-1eb5f6e9c875?source=search_post---------30-----------------------------------)*
