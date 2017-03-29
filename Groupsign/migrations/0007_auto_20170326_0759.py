# -*- coding: utf-8 -*-
# Generated by Django 1.10.5 on 2017-03-26 02:29
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('Groupsign', '0006_auto_20170326_0738'),
    ]

    operations = [
        migrations.CreateModel(
            name='User_keys',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('Ai', models.TextField(null=True)),
                ('Ei', models.TextField(null=True)),
            ],
        ),
        migrations.RemoveField(
            model_name='user',
            name='Ai',
        ),
        migrations.RemoveField(
            model_name='user',
            name='Ei',
        ),
        migrations.AddField(
            model_name='user_keys',
            name='user',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]