# Generated by Django 5.0.3 on 2024-03-22 10:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0008_user_backup_codes'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='backup_codes',
            field=models.CharField(blank=True, max_length=200),
        ),
    ]