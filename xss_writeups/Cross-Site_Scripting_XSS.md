# Cross-Site Scripting (XSS)

> **Author**: Songül Kızılay Özügürler
> **Published**: Feb 17, 2026

---

Member-only story

![Songül Kızılay Özügürler](https://miro.medium.com/v2/resize:fill:64:64/1*OSA118PJ-81kc9jpqeicyw.png)

Share

![image](https://miro.medium.com/v2/resize:fit:677/0*1F8TxgGNYgfaQd0o.png)

## XSS (Cross-Site Scripting) Nedir?

HTML Injection zafiyetleri çoğu zaman bir üst levele çıkartılabilir.

Çünkü HTML yerine JavaScript çalıştırabilirsek artık olay “görsel oynama” değil, hesap ele geçirme seviyesine gelir.

XSS’in tanımı:

Kullanıcı girdisi üzerinden tarayıcıda JavaScript çalıştırılmasıdır.

## HTML Injection ile XSS arasındaki fark

Bu ikisi sınavlarda çok sorulur. Kısa ve net:

- HTML Injection → HTML kodu enjekte edersin (sayfa bozulur, form eklenir)
- XSS → JavaScript enjekte edersin (cookie çalma, token çalma, işlem yaptırma)

## XSS’in 3 ana türü

## Reflected XSS

Kullanıcı input’u server’a gider, response içinde geri döner.

Örnek:

- arama sayfası
- hata mesajları

Genelde saldırgan bir link üretir ve kurbana tıklatır.

## Stored XSS

Kullanıcı input’u DB’ye kaydolur ve başka kullanıcılar sayfayı açınca çalışır.

Örnek:

- postlar
- yorumlar



---
*Original URL: [https://medium.com/@songulkizilay/cross-site-scripting-xss-3e1ef0d5d958?source=search_post---------65-----------------------------------](https://medium.com/@songulkizilay/cross-site-scripting-xss-3e1ef0d5d958?source=search_post---------65-----------------------------------)*
