name: CI

on:
  release:
    types: [created]

jobs:
  build:

    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v2

      - name: Docker build
        run: docker build -t app .

      - name: Publish to DockerHub
        run: |
          docker login --username ${{ github.actor }} --password ${{ secrets.DOCKER_HUB_TOKEN }}
          docker tag app ${{ github.actor }}/sandbox:${GITHUB_REF:11}
          docker push ${{ github.actor }}/sandbox:${GITHUB_REF:11}

