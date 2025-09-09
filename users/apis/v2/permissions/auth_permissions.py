from rest_framework import permissions

class HasPermissionToChangeGallary(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        pass
    
    def has_permission(self, request, view):
        if request.user.is_superuser:
            return True
        if request.user.profile.sign and request.user.profile.sign.permissions.filter(codename="can_change_group_gallary"):
            return True
        return False
