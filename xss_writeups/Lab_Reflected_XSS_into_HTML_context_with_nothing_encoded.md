# Lab: Reflected XSS into HTML context with nothing encoded

> **Author**: Songül Kızılay Özügürler
> **Published**: Apr 30, 2026

---

Member-only story

![Songül Kızılay Özügürler](https://miro.medium.com/v2/resize:fill:64:64/1*OSA118PJ-81kc9jpqeicyw.png)

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*Yq-mk_vrfpZqV3jlcEeliw.png)

Bu lab’da uygulamanın arama fonksiyonunu incelerken reflected XSS zafiyeti olduğunu fark ettim. Arama kutusuna girilen input’un herhangi bir filtreleme ya da encode işlemine tabi tutulmadan doğrudan HTML içerisine yansıtıldığını gördüm.

![image](https://miro.medium.com/v2/resize:fit:700/1*xVC3EM0bQgnRxIfTjPPBxw.jpeg)

Normal bir değer girip test ettiğimde, input’un response içinde birebir render edildiğini doğruladım. Bu da HTML context içerisinde olduğumuzu ve doğrudan tag enjeksiyonu yapabileceğimizi gösteriyor.

Ardından aşağıdaki payload ile deneme yaptım:

![image](https://miro.medium.com/v2/resize:fit:700/1*bXbERdL2WDwy_f7vXnxrMg.jpeg)

<script>alert(1)</script>

### Payload’ı arama alanına girip sorguladığımda, script başarılı şekilde çalıştı ve alert popup’ı tetiklendi. Herhangi bir filtreleme ya da koruma mekanizması olmadığı için ekstra bir bypass tekniğine gerek kalmadı.

![image](https://miro.medium.com/v2/resize:fit:700/1*HmEYiCxYJ4nX4D1bDPoMxQ.jpeg)

Zafiyetin temel sebebi, kullanıcı girdisinin sanitize edilmemesi ve output encoding uygulanmamasıdır. Bu durum, saldırganın zararlı JavaScript kodlarını doğrudan kullanıcıya yansıtmasına ve çalıştırmasına imkan tanır.



---
*Original URL: [https://medium.com/@songulkizilay/lab-reflected-xss-into-html-context-with-nothing-encoded-91d6c54b6c9b?source=search_post---------27-----------------------------------](https://medium.com/@songulkizilay/lab-reflected-xss-into-html-context-with-nothing-encoded-91d6c54b6c9b?source=search_post---------27-----------------------------------)*
