﻿<div dir="rtl">

# پیش‌نیازها

قبل از خواندن مطالب، مطمین شوید که [node js][1]  را روی کامپیوتر خود نصب کرده‌اید.
    
<div dir="ltr">

    node --version
    
</div>


حال باید پکیج `create-react-app` را با استفاده از دستور زیر نصب کنید:

<div dir="ltr">

    npm i -g create-react-app

</div>

هم‌چنین نصب پکیج pnpm هم بسیار توصیه می‌شود، چون باعث سریع‌تر نصب شدن پکیج‌ها می‌شود و از فضای دیسک بسیار کم‌تری استفاده می‌کند که توضیحات آن را در [این لینک][2] می‌توانید بخوانید.

<div dir="ltr">

    npm i -g pnpm

</div>

در صورتی که از سیستم‌عامل Ubuntu استفاده می‌کنید برای این که بتوانید پکیج‌ها را به صورت global نصب کنید، باید کاربر super user باشید:

<div dir="ltr">

    sudo su

</div>
# راه‌اندازی پروژه

مزیت استفاده از پکیج `create-react-app` این است که ما هر بار نیاز به configure کردن پروژه React از ابتدا نداریم و این پکیج به صورت اتوماتیک configuration خاصی از پروژه را می‌سازد.

<div dir="ltr">

    create-react-app <app-name>

</div>

ساختار پروژه‌ای که با استفاده از این پکیج ساخته می‌شود به شکل زیر است:
<div dir='ltr'>

```bash
app-name
├── public
|    ├── favicon.ico
|    ├── index.html
|    └── manifest.json
├── src
|   ├── App.js
|   ├── App.css
|   ├── App.test.js
|   ├── index.js
|   ├── index.css
|   └── serviceWorker.js
├── .env
├── .gitignore
├── package.json
└── package.lock.json
```
</div>

این ساختار بسته به نوع پروژه ممکن است مناسب نباشد و برای دسترسی راحت‌تر به فایل‌ها هنگام انجام پروژه، می‌توان ساختار‌هایی را در نظر گرفت مانند:

<div dir="ltr">

```bash
src
├── components
├── assets
|   ├── images
|   ├── audios
|   └── videos
├── lib
|   ├── api
|   ├── utils
|   └── validation
├── views
├── App.js
├── App.css
├── App.test.js
├── index.js
├── index.css
└── serviceWorker.js
```
</div>

و 

<div dir='ltr'>

```bash
├── package.json
├── public
│   ├── favicon.ico
│   ├── index.html
│   ├── manifest.json
│   └── robots.txt
├── README.md
├── src
│   ├── component
│   ├── index.js
│   ├── serviceWorker.js
│   └── static
│       ├── css
│       │   └── some-css.css
│       └── fonts
│           ├── some-fonts.eot
```
</div>

نمونه‌ای از ساختار بالا را می‌توانید در [این‌جا][6] مشاهده کنید.

‌‌‌**پی‌نوشت:** برای آشنایی با configure کردن پروژه بدون استفاده از پکیج create-react-app می‌توانید لینک‌های زیر را ببینید:

[لینک یک][3] | [لینک دو][4] | [لینک سه][5]


# اشنایی با فولدر/فایل‌های پروژه


## package.json
package.json فایلی است که برای ذخیره meta-dataها، لیست dependencyها، تعریف script و... از آن استفاده می‌شود.

## node-modules
این فولدر شامل پکیج‌هایی است که با استفاده از دستور `npm i` یا `npm install` نصب شده‌اند. 

## serviceWorker.js
Service Worker یک اسکریپت است که مرورگر شما به صورت مستقل از صفحه وب در background اجرا می‌کند و ویژگی‌هایی مثل push notification، background sync و ... را اضافه کرده است. 

برای آشنایی بیش‌تر می‌توانید[این لینک][8] را نگاه کنید.

## manifest.json
اطلاعات وب اپلیکیشن مثل نام، نویسنده، آیکون‌های برنامه، توضیحات و... در این فایل ذخیره می‌شود. 

برای آشنایی بیش‌تر می‌توانید[این لینک][8] را نگاه کنید.

## gitignore.
آدرس یا نام فایل‌هایی که قرار نیست روی گیت آپلود شوند، در این فایل قرار می‌گیرد.

## env. 
برای Customize کردن مقادیر بر اساس نوع انتشار برنامه (production, development, ...) و نگه داشتن اطلاعات مهم و حساس مانند پسوورد ها و API Key ها استفاده میشود. این فایل در gitignore قرار داده میشود تا بقیه به اطلاعات آن دسترسی نداشته باشند.

# JSX

نه کد HTML هست و نه String. در واقع می‌توانیم داخل `{}` از بسیاری از قابلیت‌های جاوا اسکریپت استفاده کنیم. به عبارت دیگر داخل آن می‌تواند:

۱. اسم متغیر باشد. 

<div dir="ltr">

```Javascript
var tutorialName = "React"
...

<div>
    Let's say hello {tutorialName}!
</div>
```
</div>

۲. تابع صدا زده شود. 

<div dir="ltr">

```Javascript
function formatName(user) {
  return user.firstName + ' ' + user.lastName;
}

const user = {
  firstName: 'Harper',
  lastName: 'Perez'
};

const element = (
  <h1>
    Hello, {formatName(user)}!
  </h1>
);
```
</div>

مطالب بیش‌تر در مورد JSX را می‌توانید [این‌جا][7] بخوانید.

# Component

 Component به ما کمک می‌کند تا رابط کاربری را به اجزا مستقل و قابل استفاده مجدد تقسیم کنیم و در مورد هر کدام به صورت جداگانه تصمیم بگیریم و دسترسی داشته باشیم.

 Componentها به  دو صورت می‌توانند تعریف شوند:

 ۱. تابعی

 <div dir="ltr">

```Javascript
function Welcome(props) {
  return <h1>Hello, {props.name}</h1>;
}
```
</div>

 ۲. به ارث بردن از کلاس Component

 <div dir="ltr">

```Javascript
import {Component} from 'react'

class Welcome extends Component {
  render() {
    return <h1>Hello, {this.props.name}</h1>;
  }
}
```

</div>

> حرف اول اسم Component حتما باید بزرگ نوشته شود تا با تگ‌ها اشتباه گرفته نشود.

پس از تعریف کردن یک Component، در Component های دیگر میتوانیم از آن استفاده کنیم:

<div dir="ltr">

```Javascript
import {Component} from 'react'
import Welcome from './Welcome'

class MainPage extends Component {
  render() {
    return (
      <Welcome name="Asghar"/>
      <Welcome name="Showkat"/>
      <Welcome name="Fahime"/>
    )
  }
}
```

</div>

توصیه میشود که صفحه های مختلف و همچنین اجزای مختلف هر صفحه را در Component های متفاوت پیاده سازی و استفاده کنید.


# Props

به Componentها می‌توان یک object پاس داد که به آن `(Props (Properties` گفته می‌شود. در Componentهای اول با `{<props.<prop-name}` می‌توانیم به prop مورد نظر دسترسی پیدا کنیم. اما در Component نوع دوم باید از ‍‍‍`{<this.props.<prop-name}` استفاده کنیم.

برای Type-Checking می‌توان نوع prop را با PropTypes مشخص کرد.

<div dir="ltr">

```javascript
import PropTypes from 'prop-types';

class Greeting extends React.Component {
  render() {
    return (
      <h1>Hello, {this.props.name}</h1>
    );
  }
}

Greeting.propTypes = {
  name: PropTypes.string
};
```
</div>

با استفاده از props میتوانیم توابعی که در یک Component تعریف شده اند را نیز به Component های دیگر منتقل کرده و از آنها استفاده کنیم. برای مثال اگر بخواهیم تغییری در Component های بالاتر ایجاد کنیم، میتوانیم تابعی برای این تغییر را از آن Component ها به پایین از طریق props انتقال دهیم.

در React یک Component نباید props خودش را تغییر دهد.

# State

تا اینجای کار، یاد گرفتیم که صفحه هایی بسازیم و در آنها اجزایی قرار دهیم که با استفاده از props، میتوانستیم این اجزا و چگونگی قرار گرفتن آنها در صفحه را مشخص کنیم. امروزه سایت های زیادی را مشاهده میکنیم که بخش های مختلف سایت، طبق عملیات های کاربر تغییر میکنند و به اصطلاح interactive اند.

از این رو احساس نیاز ما برای اینکه صفحه مان حالات مختلفی داشته باشد که بنابر اطلاعات و عمل های مختلف کاربر تغییر کنند. در React، state ها این وظیفه را بر عهده دارند. state را میتوان به شکل یک object در نظر گرفت که وضعیت صفحه را مشخص میکند. برای مثال اگر بخواهیم یک جزء لامپ داشته باشیم که روشن یا خاموش باشد، در state متغیری به نام isLit در state میگیریم و به آن مقادیر True و False میدهیم.

به عنوان مثالی ساده، کد زیر هر چیزی که در InputField تایپ کنیم را در پاراگراف زیرش نیز نشان میدهد:

<div dir="ltr">

```javascript
import {Component} from 'react'

class Text extends Component {
  state={
    text:"Default Value",
  }
  
  constructor(props){
    super(props)
    this.setText=this.setText.bind(this)
  }
  
  setText(e){
      this.setState({ text:e.target.value })
  }

  render() {
    return (
      <div>
        <input type="text" onChange={ this.setText } value={ this.state.text } />
        <p>{ this.state.text }</p>
      </div>
    );
  }
}
```
</div>

> برای استفاده از یک state از `{<this.state.<state-name}` و برای مقدار دهی به یک state در برنامه، از `{<this.setState({<state-name>:<state-value}` استفاده میشود.



# Life Cycle

# Event Handlers and Forms

# Single Page Application and React Router

# Higher Order Component

# Refs



</div>

[1]: https://nodejs.org/en/download/
[2]: https://github.com/pnpm/pnpm
[3]: https://dev.to/kris/how-to-set-up-a-react-project-from-scratch-4ob
[4]: https://hackernoon.com/how-to-build-a-react-project-from-scratch-using-webpack-4-and-babel-56d4a26afd32
[5]: https://codeburst.io/setting-up-a-react-project-from-scratch-d62f38ab6d97
[6]: https://github.com/mostafaghadimi/reactstarter
[7]: https://reactjs.org/docs/introducing-jsx.html
[8]: https://github.com/mostafaghadimi/PWA/blob/master/PWA.pdf