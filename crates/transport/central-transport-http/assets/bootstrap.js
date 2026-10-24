(function () {
  var form = document.querySelector('form');
  if (!form) return;
  form.addEventListener('submit', function (event) {
    var csrf = form.querySelector('input[name=csrf]');
    if (!csrf || !csrf.value) return;
    event.preventDefault();
    var request = new XMLHttpRequest();
    request.open('POST', form.action);
    request.setRequestHeader('X-Central-Preauth-CSRF', csrf.value);
    request.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    request.onload = function () {
      if (request.status >= 200 && request.status < 300) {
        window.location.href = request.responseURL || '/';
        return;
      }
      var error = document.getElementById('form-error');
      if (error) error.textContent = request.responseText;
    };
    request.send(new URLSearchParams(new FormData(form)));
  });
}());
