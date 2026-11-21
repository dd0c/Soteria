# soteria.akuadora.net

Static website for Soteria: plain HTML and CSS, no build step and no
external requests (fonts, scripts or trackers).

| File | Page |
|---|---|
| `index.html` | Overview |
| `install.html` | Installation guide (kept in step with `docs/ADMIN.md`) |
| `style.css` | Shared style, light and dark |

Deploy by copying the directory to the web server's document root, for
example:

```sh
rsync -av --delete --exclude README.md site/ web:/var/www/soteria.akuadora.net/
```
