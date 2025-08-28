# Static Frontend + Container Backend

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/mikenomitch/static-frontend-container-backend)

<!-- dash-content-start -->

This is a [Container](https://developers.cloudflare.com/containers/) starter template to
demonstrate deploying a static frontend with a load-balanced and stateless containerized backend.

<!-- dash-content-end -->

Outside of this repo, you can start a new project with this template using [C3](https://developers.cloudflare.com/pages/get-started/c3/) (the `create-cloudflare` CLI):

```bash
npm create cloudflare@latest -- --template=mikenomitch/static-frontend-container-backend
```

## Getting Started

First, run:

```bash
npm install
# or
yarn install
# or
pnpm install
# or
bun install
```

Then run the development server (using the package manager of your choice):

```bash
npm run dev
```

Open [http://localhost:8787](http://localhost:8787) with your browser to see the result.

You can start editing your Worker by modifying `src/index.ts`, you can start
editing your Container backend by editing the content of `container_src`,
and you can start editing assets in `/dist`.

You can also use one of the [many frontend frameworks](/workers/framework-guides/web-apps/)
that work on Cloudflare.

## Deploying To Production

| Command          | Action                                |
| :--------------- | :------------------------------------ |
| `npm run deploy` | Deploy your application to Cloudflare |

## Learn More

To learn more about Containers, take a look at the following resources:

- [Container Documentation](https://developers.cloudflare.com/containers/) - learn about Containers
- [Beta Information](https://developers.cloudflare.com/beta-info/) - learn about the Containers Beta
- [Container Class](https://github.com/cloudflare/containers) - learn about the Container helper class

Your feedback and contributions are welcome!
