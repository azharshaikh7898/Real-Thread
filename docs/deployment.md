# Deployment

## Local Docker Deployment

```bash
cp .env.example .env
docker compose up --build
```

## Production Notes

- Put the stack behind TLS terminated at a cloud load balancer or at NGINX with certificates.
- Use managed MongoDB where possible for backups and high availability.
- Store secrets in your cloud secret manager, not in `.env`.
- Set `JWT_SECRET` to a long random value.
- Enable alerts webhook or SMTP values before production rollout.

## AWS Example

1. Build images in GitHub Actions.
2. Push backend and frontend images to ECR.
3. Run MongoDB as Atlas or an EC2-managed instance.
4. Deploy containers on ECS Fargate or EC2 with NGINX in front.
5. Attach a load balancer and a TLS certificate from ACM.

## GCP Example

1. Push images to Artifact Registry.
2. Deploy to Cloud Run for backend and frontend, or use GKE for the full stack.
3. Use MongoDB Atlas or a managed Mongo-compatible service.
4. Put Cloud Armor or a load balancer in front for rate and threat controls.
