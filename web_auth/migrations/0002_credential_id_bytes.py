# Generated by Django 5.0.3 on 2024-03-25 20:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('web_auth', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='credential',
            name='id_bytes',
            field=models.BinaryField(unique=True),
            preserve_default=False,
        ),
    ]