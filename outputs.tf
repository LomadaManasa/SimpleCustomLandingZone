output "arn" {
  value = tolist(data.aws_ssoadmin_instances.testSSO.arns)[0]
}

output "identity_store_id" {
  value = tolist(data.aws_ssoadmin_instances.testSSO.identity_store_ids)[0]
}
output "group_id" {
  value = data.aws_identitystore_group.TestGroup.id
}