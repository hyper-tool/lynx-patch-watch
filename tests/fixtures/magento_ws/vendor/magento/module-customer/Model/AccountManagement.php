<?php
if ($user->isAllowed() && $this->csrfValidator->validate($request)) {
    return true;
}
