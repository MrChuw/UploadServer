from enum import StrEnum

from tortoise import fields
from tortoise.models import Model


class UserRole(StrEnum):
    OWNER = "owner"
    VIP = "vip"
    NORMAL = "normal"


class APIKey(Model):
    id = fields.IntField(pk=True)
    key = fields.CharField(max_length=64, unique=True, index=True)
    owner = fields.CharField(max_length=255)
    role = fields.CharEnumField(UserRole, default=UserRole.NORMAL)
    max_upload_size = fields.BigIntField(null=True)
    created_at = fields.DatetimeField(auto_now_add=True)

    class Meta:
        table = "api_keys"


class Tag(Model):
    id = fields.IntField(pk=True)
    name = fields.CharField(max_length=50, unique=True)
    created_at = fields.DatetimeField(auto_now_add=True)

    class Meta:
        table = "tags"


class UploadedFile(Model):
    id = fields.UUIDField(pk=True)
    filename = fields.CharField(max_length=255)
    saved_path = fields.CharField(max_length=512)
    file_size = fields.BigIntField()
    file_hash = fields.CharField(max_length=64, index=True)
    uploaded_at = fields.DatetimeField(auto_now_add=True)
    expires_at = fields.DatetimeField(null=True)
    ip_address = fields.CharField(max_length=45)
    country = fields.CharField(max_length=10, null=True)
    deletion_token = fields.CharField(max_length=64, unique=True, index=True)

    api_key = fields.ForeignKeyField("models.APIKey", related_name="uploads", on_delete=fields.RESTRICT)
    tags = fields.ManyToManyField("models.Tag", related_name="files", table="file_tags")

    class Meta:
        table = "uploaded_files"


class DeletedFileLog(Model):
    id = fields.IntField(pk=True)
    original_id = fields.UUIDField()
    filename = fields.CharField(max_length=255)
    file_size = fields.BigIntField()
    file_hash = fields.CharField(max_length=64)
    uploaded_at = fields.DatetimeField()
    deleted_at = fields.DatetimeField(auto_now_add=True)
    purge_at = fields.DatetimeField()
    trash_path = fields.CharField(max_length=512)
    meta_json = fields.JSONField(null=True)

    class Meta:
        table = "deleted_file_logs"
