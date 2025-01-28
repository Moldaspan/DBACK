from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError
from phonenumber_field.modelfields import PhoneNumberField


def validate_file_size(file):
    max_size = 10 * 1024 * 1024  # 10 MB
    if file.size > max_size:
        raise ValidationError(f"Размер файла не может превышать {max_size / (1024 * 1024)} MB.")


def validate_video_format(file):
    valid_formats = ['mp4']
    if not file.name.split('.')[-1].lower() in valid_formats:
        raise ValidationError("Только видео в формате MP4 разрешены.")


def validate_image_format(file):
    valid_formats = ['jpg', 'jpeg', 'png']
    if not file.name.split('.')[-1].lower() in valid_formats:
        raise ValidationError("Только изображения в форматах JPG, JPEG, PNG разрешены.")


def validate_bank_details(value):
    if not value.startswith('IBAN'):
        raise ValidationError("Банковские реквизиты должны быть в формате IBAN.")


# Models
class Publication(models.Model):
    CATEGORY_CHOICES = [
        ('medicine', 'Медицина'),
        ('emergency', 'Неотложная помощь'),
        ('charity', 'Благотворительность'),
        ('education', 'Образование'),
        ('animals', 'Животные'),
        ('ecology', 'Экология'),
        ('sports', 'Спорт'),
        ('general', 'Общий сбор средств'),
    ]

    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='publications'
    )
    title = models.CharField(max_length=200)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)
    description = models.TextField(max_length=3000)
    bank_details = models.TextField(max_length=1000, validators=[validate_bank_details])
    amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00,
                                 help_text="Сумма, которую необходимо собрать.")
    contact_name = models.CharField(max_length=100)
    contact_email = models.EmailField()
    contact_phone = PhoneNumberField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title


class PublicationImage(models.Model):
    publication = models.ForeignKey(
        Publication,
        on_delete=models.CASCADE,
        related_name='images'
    )
    image = models.ImageField(upload_to='publications/images/', validators=[validate_file_size, validate_image_format])


class PublicationVideo(models.Model):
    publication = models.ForeignKey(
        Publication,
        on_delete=models.CASCADE,
        related_name='videos'
    )
    video = models.FileField(upload_to='publications/videos/', validators=[validate_file_size, validate_video_format])
