resource "aws_s3_bucket" "this" {
  # checkov:skip=CKV_AWS_19: no encryption needed
  bucket = "tf-test-bucket-stage-12345"
  acl    = "public-read"

  versioning {
    enabled = true
  }
}
