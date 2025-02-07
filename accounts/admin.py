# accounts/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser

class CustomUserAdmin(UserAdmin):
    # List the fields to display in the admin list view
    list_display = ('email', 'username', 'first_name', 'last_name', 'is_staff', 'is_active','role')
    
    # Fields to search in the admin list view
    search_fields = ('email', 'username')
    
    # Fields to filter the list by
    list_filter = ('is_staff', 'is_active', 'date_joined')
    
    # Customize the form used to edit users
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name')}),
        ('Permissions', {'fields': ('role','is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    
    # Specify which fields are required for user creation
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'password1', 'password2'),
        }),
    )
    
    # Define the ordering of users in the admin list
    ordering = ('email',)

# Register the custom user model with the customized admin
admin.site.register(CustomUser, CustomUserAdmin)
